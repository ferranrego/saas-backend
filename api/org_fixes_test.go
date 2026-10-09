package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/saas-backend/api/apicommon"
	"github.com/vocdoni/saas-backend/db"
	"github.com/vocdoni/saas-backend/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// TestAPIKeyConfinedToItsOrganization covers the regression where an API key inherited every
// role of its creating user: a key minted for one organization could act on any unrelated
// organization the creator belonged to. A key must only reach its own organization and the
// organizations it manages.
func TestAPIKeyConfinedToItsOrganization(t *testing.T) {
	c := qt.New(t)
	token := testCreateUser(t, "apikeyscopepass123")
	me := requestAndParse[apicommon.UserInfo](t, http.MethodGet, token, nil, usersMeEndpoint)

	// the key's organization (integrator) and an unrelated organization the same user admins
	orgAddr := testCreateOrganization(t, token)
	org, err := testDB.Organization(orgAddr)
	c.Assert(err, qt.IsNil)
	org.IntegratorLimits = &db.IntegratorLimits{MaxManagedOrgs: 2}
	c.Assert(testDB.SetOrganization(org), qt.IsNil)

	otherToken := testCreateUser(t, "apikeyotherpass123")
	otherOrgAddr := testCreateOrganization(t, otherToken)
	c.Assert(testDB.AddUserToOrganization(me.Email, otherOrgAddr, db.AdminRole), qt.IsNil)

	// mint a members:write + managed:write key for the integrator org
	created := requestAndParse[apicommon.CreateAPIKeyResponse](t, http.MethodPost, token,
		&apicommon.CreateAPIKeyRequest{Label: "scoped", Scopes: []string{ScopeMembersWrite, ScopeManagedWrite}},
		"integrator", "organizations", orgAddr.String(), "apikeys")
	apiKey := created.Secret

	// the JWT session still reaches both organizations
	requestAndAssertCode(http.StatusOK, t, http.MethodGet, token, nil,
		"organizations", otherOrgAddr.String(), "members")

	// the key reaches its own organization...
	requestAndAssertCode(http.StatusOK, t, http.MethodGet, apiKey, nil,
		"organizations", orgAddr.String(), "members")

	// ...and an organization it manages...
	managed := requestAndParse[apicommon.OrganizationInfo](t, http.MethodPost, apiKey,
		&apicommon.CreateManagedOrganizationRequest{
			OrganizationInfo: apicommon.OrganizationInfo{Type: string(db.CompanyType)},
		}, "integrator", "organizations")
	requestAndAssertCode(http.StatusOK, t, http.MethodGet, apiKey, nil,
		"organizations", managed.Address.String(), "members")

	// ...but not the unrelated organization, even though its creating user is an admin there
	requestAndAssertCode(http.StatusUnauthorized, t, http.MethodGet, apiKey, nil,
		"organizations", otherOrgAddr.String(), "members")
}

// TestUpsertMemberEnforcesMemberQuota covers the regression where the single-member PUT skipped
// the member-base quota the bulk POST enforces: creations past the plan limit must be refused,
// while edits of existing members at the limit stay allowed.
func TestUpsertMemberEnforcesMemberQuota(t *testing.T) {
	c := qt.New(t)
	token := testCreateUser(t, "memberquotapass123")
	orgAddr := testCreateOrganization(t, token)

	members := postOrgMembers(t, token, orgAddr, newOrgMembers(2)...)
	c.Assert(members, qt.HasLen, 2)

	// shrink the default plan's member limit to the current member base
	reducedFreePlan := *mockFreePlan
	reducedFreePlan.Organization.MaxCensus = 2
	c.Assert(testDB.SetPlan(&reducedFreePlan), qt.IsNil)
	c.Cleanup(func() { c.Assert(testDB.SetPlan(mockFreePlan), qt.IsNil) })

	// creating one more member via PUT must be refused with the quota error
	newMember := newOrgMembers(3)[2]
	apiErr := putOrgMemberAndExpectError(t, token, orgAddr, newMember)
	c.Assert(apiErr.Code, qt.Equals, errors.ErrExceedsOrganizationMembersLimit.Code)

	// editing an existing member at the limit is still allowed
	edited := members[0]
	edited.Phone = "" // the API returns a trimmed hash, not a phone number
	edited.Name = "Edited At Limit"
	putOrgMember(t, token, orgAddr, edited)
}

// TestAcceptInvitationWithExistingDifferentRole covers the regression where accepting an
// invitation only checked for the exact invited role: a user already holding a different role
// got a second membership entry for the same organization.
func TestAcceptInvitationWithExistingDifferentRole(t *testing.T) {
	c := qt.New(t)
	adminToken := testCreateUser(t, "inviteadminpass123")
	admin := requestAndParse[apicommon.UserInfo](t, http.MethodGet, adminToken, nil, usersMeEndpoint)
	orgAddr := testCreateOrganization(t, adminToken)

	userToken := testCreateUser(t, "inviteduserpass123")
	user := requestAndParse[apicommon.UserInfo](t, http.MethodGet, userToken, nil, usersMeEndpoint)

	// the user already holds a role in the organization...
	c.Assert(testDB.AddUserToOrganization(user.Email, orgAddr, db.ViewerRole), qt.IsNil)

	// ...and an invitation for a different role is accepted
	c.Assert(testDB.CreateInvitation(&db.OrganizationInvite{
		ID:                  bson.NewObjectID(),
		InvitationCode:      "fix33code",
		OrganizationAddress: orgAddr,
		CurrentUserID:       admin.ID,
		NewUserEmail:        user.Email,
		Role:                db.ManagerRole,
		Expiration:          time.Now().Add(time.Hour),
	}), qt.IsNil)
	requestAndAssertCode(http.StatusConflict, t, http.MethodPost, userToken,
		&apicommon.AcceptOrganizationInvitation{Code: "fix33code"},
		"organizations", orgAddr.String(), "users", "accept")

	// the user keeps a single membership entry with the original role
	dbUser, err := testDB.UserByEmail(user.Email)
	c.Assert(err, qt.IsNil)
	entries := 0
	for _, o := range dbUser.Organizations {
		if o.Address == orgAddr {
			entries++
			c.Assert(o.Role, qt.Equals, db.ViewerRole)
		}
	}
	c.Assert(entries, qt.Equals, 1)
}

// TestGroupUpdateRejectsOverlappingLists covers the regression where a member present in both
// addMembers and removeMembers was revoked from the group censuses yet kept in the group.
func TestGroupUpdateRejectsOverlappingLists(t *testing.T) {
	c := qt.New(t)
	token := testCreateUser(t, "groupoverlapass123")
	orgAddr := testCreateOrganization(t, token)

	members := postOrgMembers(t, token, orgAddr, newOrgMembers(2)...)
	c.Assert(members, qt.HasLen, 2)

	group := requestAndParse[apicommon.OrganizationMemberGroupInfo](t, http.MethodPost, token,
		&apicommon.CreateOrganizationMemberGroupRequest{
			Title:     "Overlap Group",
			MemberIDs: []string{members[0].ID},
		}, "organizations", orgAddr.String(), "groups")

	// a member in both lists is refused before anything is touched
	requestAndAssertError(errors.ErrInvalidData, t, http.MethodPut, token,
		&apicommon.UpdateOrganizationMemberGroupsRequest{
			AddMembers:    []string{members[1].ID},
			RemoveMembers: []string{members[1].ID},
		}, "organizations", orgAddr.String(), "groups", group.ID)

	// the group is unchanged
	updated, err := testDB.OrganizationMemberGroup(group.ID, orgAddr)
	c.Assert(err, qt.IsNil)
	c.Assert(updated.MemberIDs, qt.DeepEquals, []string{members[0].ID})
}

// TestCreateSubOrganizationWithinPlan covers the regression where creating a suborganization
// always failed: the parent check took the length of a fixed-size address, never zero. Within the
// plan's limit a suborganization is created; past it the dedicated 400 is returned.
func TestCreateSubOrganizationWithinPlan(t *testing.T) {
	c := qt.New(t)
	token := testCreateUser(t, "suborgplanpass123")
	parentAddr := testCreateOrganization(t, token)

	// the essential plan allows one suborganization
	parent, err := testDB.Organization(parentAddr)
	c.Assert(err, qt.IsNil)
	parent.Subscription.PlanID = mockEssentialPlan.ID
	c.Assert(testDB.SetOrganization(parent), qt.IsNil)

	subOrgInfo := &apicommon.OrganizationInfo{
		Type:   string(db.CompanyType),
		Parent: &apicommon.OrganizationInfo{Address: parentAddr},
	}
	sub := requestAndParse[apicommon.OrganizationInfo](t, http.MethodPost, token, subOrgInfo, organizationsEndpoint)
	c.Assert(sub.Parent, qt.Not(qt.IsNil))
	c.Assert(sub.Parent.Address, qt.Equals, parentAddr)

	// the plan is now exhausted
	requestAndAssertError(errors.ErrMaxSubOrgsReached, t, http.MethodPost, token, subOrgInfo, organizationsEndpoint)

	// a suborganization cannot be the parent of another one
	nested := &apicommon.OrganizationInfo{
		Type:   string(db.CompanyType),
		Parent: &apicommon.OrganizationInfo{Address: sub.Address},
	}
	requestAndAssertError(errors.ErrMalformedBody, t, http.MethodPost, token, nested, organizationsEndpoint)
}

// TestOrganizationBillingEmailAdminOnly covers the regression where the public organization
// endpoint returned the subscription billing email to anyone. Only admins of each organization in
// the parent chain see its billing email, on the public endpoint and on /users/me.
func TestOrganizationBillingEmailAdminOnly(t *testing.T) {
	c := qt.New(t)
	parentToken := testCreateUser(t, "billingparentpass123")
	parentAddr := testCreateOrganization(t, parentToken)
	childToken := testCreateUser(t, "billingchildpass123")
	childAddr := testCreateOrganization(t, childToken)
	viewerToken := testCreateUser(t, "billingviewerpass123")
	viewer := requestAndParse[apicommon.UserInfo](t, http.MethodGet, viewerToken, nil, usersMeEndpoint)
	c.Assert(testDB.AddUserToOrganization(viewer.Email, childAddr, db.ViewerRole), qt.IsNil)

	// give both organizations a billing email and link the child to the parent
	for addr, email := range map[common.Address]string{parentAddr: "parent@billing.test", childAddr: "child@billing.test"} {
		org, err := testDB.Organization(addr)
		c.Assert(err, qt.IsNil)
		org.Subscription.Email = email
		if addr == childAddr {
			org.Parent = parentAddr
		}
		c.Assert(testDB.SetOrganization(org), qt.IsNil)
	}

	getInfo := func(token string) *apicommon.OrganizationInfo {
		info := requestAndParse[apicommon.OrganizationInfo](t, http.MethodGet, token, nil,
			"organizations", childAddr.String())
		c.Assert(info.Subscription, qt.Not(qt.IsNil))
		c.Assert(info.Parent, qt.Not(qt.IsNil))
		c.Assert(info.Parent.Subscription, qt.Not(qt.IsNil))
		return &info
	}

	// anonymous and non-admin members get no billing email at all
	for _, token := range []string{"", viewerToken} {
		info := getInfo(token)
		c.Assert(info.Subscription.Email, qt.Equals, "")
		c.Assert(info.Parent.Subscription.Email, qt.Equals, "")
	}
	// the child's admin gets the child's email, but not the parent's it does not administer
	info := getInfo(childToken)
	c.Assert(info.Subscription.Email, qt.Equals, "child@billing.test")
	c.Assert(info.Parent.Subscription.Email, qt.Equals, "")

	// /users/me applies the same rule per organization
	viewerMe := requestAndParse[apicommon.UserInfo](t, http.MethodGet, viewerToken, nil, usersMeEndpoint)
	c.Assert(viewerMe.Organizations, qt.HasLen, 1)
	c.Assert(viewerMe.Organizations[0].Organization.Subscription.Email, qt.Equals, "")
	childMe := requestAndParse[apicommon.UserInfo](t, http.MethodGet, childToken, nil, usersMeEndpoint)
	c.Assert(childMe.Organizations, qt.HasLen, 1)
	c.Assert(childMe.Organizations[0].Organization.Subscription.Email, qt.Equals, "child@billing.test")
	c.Assert(childMe.Organizations[0].Organization.Parent.Subscription.Email, qt.Equals, "")
}
