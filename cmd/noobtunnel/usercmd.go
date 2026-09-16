package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// runUser manages control node accounts from the command line. It is the way
// back in when the web UI password is forgotten, and the way to seed accounts on
// a fresh server.
func runUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: noobtunnel user <list|add|set-password|role|remove> [flags]")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return userList(rest)
	case "add", "set-password", "role", "remove":
		return userMutate(sub, rest)
	case "help", "--help", "-h":
		fmt.Print(userUsage())
		return nil
	default:
		return fmt.Errorf("unknown user subcommand %q\n\n%s", sub, userUsage())
	}
}

func userUsage() string {
	return `usage: noobtunnel user <command> [flags]

  list          list accounts
  add           create an account (fails if the name is taken)
  set-password  set an account's password, creating it if needed
  role          change an account's role (admin or viewer)
  remove        delete an account

flags:
  --state-dir DIR   control node state directory (default ` + defaultStateDir() + `)
  --username NAME   account name
  --password PW     password; omit to have one generated and printed
  --role ROLE       admin or viewer (default viewer for add, admin for bootstrap)
`
}

func userList(args []string) error {
	fs := newFlagSet("user list")
	stateDir := fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	auth, err := store.OpenAuth(*stateDir)
	if err != nil {
		return err
	}
	users := auth.Users()
	if len(users) == 0 {
		fmt.Printf("no accounts in %s yet\n", *stateDir)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tROLE\tSTATUS\tCREATED\tLAST SIGN IN")
	for _, u := range users {
		status := "active"
		if u.Disabled {
			status = "disabled"
		}
		last := "never"
		if u.LastLogin != nil {
			last = u.LastLogin.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", u.Username, u.Role, status,
			u.CreatedAt.Local().Format(time.RFC3339), last)
	}
	return w.Flush()
}

func userMutate(sub string, args []string) error {
	fs := newFlagSet("user " + sub)
	stateDir := fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "")
	username := fs.String("username", "", "account name")
	password := fs.String("password", "", "password (omit to generate one)")
	role := fs.String("role", "", "admin or viewer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("--username is required")
	}
	auth, err := store.OpenAuth(*stateDir)
	if err != nil {
		return err
	}
	targetRole := store.Role(*role)
	if targetRole != "" && !store.ValidRole(targetRole) {
		return fmt.Errorf("--role must be admin or viewer")
	}

	switch sub {
	case "remove":
		user, err := auth.FindByUsername(*username)
		if err != nil {
			return fmt.Errorf("no account named %q in %s", *username, *stateDir)
		}
		if err := auth.RemoveUser(user.ID); err != nil {
			return err
		}
		fmt.Printf("removed %s from %s\n", user.Username, *stateDir)
		return nil

	case "role":
		if targetRole == "" {
			return fmt.Errorf("--role is required (admin or viewer)")
		}
		user, err := auth.FindByUsername(*username)
		if err != nil {
			return fmt.Errorf("no account named %q in %s", *username, *stateDir)
		}
		updated, err := auth.UpdateUser(user.ID, func(u *store.User) error {
			u.Role = targetRole
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Printf("%s is now %s\n", updated.Username, updated.Role)
		return nil
	}

	// add and set-password behave the same, except that "add" refuses to
	// overwrite an existing account.
	generated := false
	if *password == "" {
		gpw, err := randomPassword()
		if err != nil {
			return err
		}
		*password = gpw
		generated = true
	}
	if sub == "add" {
		if _, err := auth.FindByUsername(*username); err == nil {
			return fmt.Errorf("account %q already exists, use set-password to change it", *username)
		}
	}
	if targetRole == "" {
		// Bootstrapping an empty server has to produce an admin.
		if !auth.HasUsers() && sub == "set-password" {
			targetRole = store.RoleAdmin
		} else if sub == "set-password" {
			if existing, err := auth.FindByUsername(*username); err == nil {
				targetRole = existing.Role
			} else {
				targetRole = store.RoleAdmin
			}
		} else {
			targetRole = store.RoleViewer
		}
	}
	user, created, err := auth.UpsertUser(*username, *password, targetRole)
	if err != nil {
		return err
	}
	action := "updated"
	if created {
		action = "created"
	}
	fmt.Printf("%s account %s (%s) in %s\n", action, user.Username, user.Role, *stateDir)
	if generated {
		fmt.Printf("password: %s\n", *password)
	}
	fmt.Println("sign in at the web UI with this account; the password is not shown again.")
	return nil
}

func randomPassword() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
