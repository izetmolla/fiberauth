// Package utils provides utility functions for the authentication system.
// This package contains helper functions that don't fit into other categories.
package utils

import (
	"bytes"
	"fmt"
	"text/template"
)

// RenderRedirectHTML renders the redirect HTML template with the provided parameters.
// This function generates an HTML page that handles OAuth callback redirects and
// stores authentication data in localStorage.
//
// Parameters:
//   - params: Optional map of parameters to pass to the template (e.g., jsData for authentication response)
//
// Returns:
//   - string: The rendered HTML string
func RenderRedirectHTML(params ...map[string]any) string {
	if len(params) == 0 || params[0] == nil {
		return "Error: No parameters provided for redirect HTML."
	}

	t, err := template.New("indexauth.html").Parse(string(`<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirecting...</title>
    <script>
        const authData = {{.jsData }}
        const currentState = JSON.parse(window.localStorage.getItem("authorization-storage") ?? "{}");
        // Get redirectUrl from query params
        const params = new URLSearchParams(window.location.search);
        const redirectUrl = params.get("redirectUrl") || currentState?.state?.redirectUrl || "/";


        console.log("Data", authData);

        window.addEventListener("DOMContentLoaded", () => {
            const appDiv = document.getElementById("app");

            if (authData?.error?.message) {
                appDiv.innerHTML = "<center><h2 style='color: red;'>" + authData.error.message + "</h2></center>";
            } else {
                appDiv.innerHTML = "<span>Authentication successful. Redirecting... " + redirectUrl + "</span>";
                window.localStorage.setItem("authorization-storage", JSON.stringify({
                    ...currentState,
                    state: {
                        ...currentState?.state,
                        redirectUrl: "",
                        isSignedIn: true,
                        ...authData
                    }
                }));
                setTimeout(() => {
                    console.log("Redirecting to:", redirectUrl);
                    window.location.replace(redirectUrl);
                }, 500);
            }

        });
    </script>
</head>

<body>
    <div id="app"></div>
</body>

</html>`))
	if err != nil {
		return fmt.Sprintf("Error parsing template: %v", err)
	}

	var buf bytes.Buffer
	ct := map[string]any{}
	if len(params) > 0 {
		ct = params[0]
	}
	if err := t.Execute(&buf, ct); err != nil {
		return fmt.Sprintf("Error executing template: %v", err)
	}
	return buf.String()
}

