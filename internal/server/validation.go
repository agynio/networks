package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/agynio/networks/internal/store"
)

const maxResourceNameLength = 64

var (
	resourceNamePattern   = regexp.MustCompile(`^[a-z0-9_-]+$`)
	openZitiSyntheticCIDR = mustParseCIDR("100.64.0.0/10")
)

func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("name must be provided")
	}
	if len(name) > maxResourceNameLength {
		return fmt.Errorf("name must be %d characters or less", maxResourceNameLength)
	}
	if !resourceNamePattern.MatchString(name) {
		return fmt.Errorf("name must match %s", resourceNamePattern.String())
	}
	return nil
}

func validateProtocol(protocol store.PrivateResourceProtocol) error {
	switch protocol {
	case store.PrivateResourceProtocolTCP, store.PrivateResourceProtocolHTTP, store.PrivateResourceProtocolHTTPS:
		return nil
	default:
		return fmt.Errorf("protocol must be tcp, http, or https")
	}
}

func validatePrincipalType(principalType store.PrincipalType) error {
	switch principalType {
	case store.PrincipalTypeAgent, store.PrincipalTypeUser, store.PrincipalTypeApp, store.PrincipalTypeGroup:
		return nil
	default:
		return fmt.Errorf("principal type must be agent, user, app, or group")
	}
}

func validatePortMapping(targetPorts []int32, interceptPorts []int32) error {
	if len(targetPorts) == 0 {
		return fmt.Errorf("target ports must be provided")
	}
	if len(targetPorts) != len(interceptPorts) {
		return fmt.Errorf("target ports and intercept ports must have the same length")
	}
	if err := validatePorts("target ports", targetPorts); err != nil {
		return err
	}
	if err := validatePorts("intercept ports", interceptPorts); err != nil {
		return err
	}
	return nil
}

func validatePorts(field string, ports []int32) error {
	seen := map[int32]struct{}{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s must be between 1 and 65535", field)
		}
		if _, ok := seen[port]; ok {
			return fmt.Errorf("%s must not contain duplicates", field)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func copyPorts(ports []int32) []int32 {
	return append([]int32{}, ports...)
}

func validateTargetHost(host string) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("target host must be provided")
	}
	return nil
}

func validateInterceptHost(host string) error {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if normalized == "" {
		return fmt.Errorf("intercept host must be provided")
	}
	if normalized == "localhost" || strings.HasSuffix(normalized, ".agyn") || strings.HasSuffix(normalized, ".svc") || strings.HasSuffix(normalized, ".cluster.local") {
		return fmt.Errorf("intercept host is reserved")
	}
	if ip := net.ParseIP(normalized); ip != nil {
		if ip.IsLoopback() || openZitiSyntheticCIDR.Contains(ip) {
			return fmt.Errorf("intercept host is reserved")
		}
	}
	return nil
}

func mustParseCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(fmt.Sprintf("parse cidr %s: %v", value, err))
	}
	return network
}
