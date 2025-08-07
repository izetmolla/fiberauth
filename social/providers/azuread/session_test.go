package azuread_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/izetmolla/fiberauth/social"
	"github.com/izetmolla/fiberauth/social/providers/azuread"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &azuread.Session{}

	a.Implements((*social.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &azuread.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &azuread.Session{}

	data := s.Marshal()
	a.Equal(`{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`, data)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &azuread.Session{}

	a.Equal(s.String(), s.Marshal())
}
