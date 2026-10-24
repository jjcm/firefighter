package protocol

import "testing"

func TestValidateExecutableContract(t *testing.T) {
	for _, name := range []string{
		"", " ", "./check", "tools/check", `tools\check`,
		"/usr/sbin/ufw delete limit 22/tcp && /usr/sbin/ufw allow 22/tcp",
		"ufw status", "/opt/local tools/check", "/usr/bin/true\t",
		"/usr/bin/true\n", "/usr/bin/true\x00", "/usr/bin/true\x1b",
		"/opt/local\u00a0tools/check", "/usr/bin/true\u0085",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateExecutable(name); err == nil {
				t.Fatalf("accepted invalid executable token %q", name)
			}
		})
	}
	for _, name := range []string{"true", "/usr/bin/true", "/bin/sh", "/not-yet-installed/check", "/opt/工具/check"} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateExecutable(name); err != nil {
				t.Fatalf("rejected executable token %q: %v", name, err)
			}
		})
	}
}
