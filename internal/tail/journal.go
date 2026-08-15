package tail

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
)

// FollowJournal tails systemd-journald for host auth (sshd, sudo, console login).
// Modern Debian often has no /var/log/auth.log — this is the sensor there.
func FollowJournal(ctx context.Context, fromStart bool, emit func(line string)) error {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return fmt.Errorf("journalctl not found (install systemd, or tail /var/log/auth.log)")
	}
	args := []string{
		"--no-pager", "-o", "short-iso",
		"-u", "ssh", "-u", "sshd",
		"-t", "sshd", "-t", "sshd-session",
		"-t", "sudo", "-t", "login",
	}
	if fromStart {
		args = append(args, "--since", "7 days ago")
	} else {
		args = append([]string{"-f", "-n", "0"}, args...)
	}
	if !fromStart {
		return runJournal(ctx, args, emit)
	}
	// Replay recent, then follow new.
	if err := runJournal(ctx, args, emit); err != nil && ctx.Err() == nil {
		return err
	}
	follow := []string{
		"-f", "-n", "0", "--no-pager", "-o", "short-iso",
		"-u", "ssh", "-u", "sshd",
		"-t", "sshd", "-t", "sshd-session",
		"-t", "sudo", "-t", "login",
	}
	return runJournal(ctx, follow, emit)
}

func runJournal(ctx context.Context, args []string, emit func(line string)) error {
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			emit(line)
		}
	}
	_ = cmd.Wait()
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return ctx.Err()
}
