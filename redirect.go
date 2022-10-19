package jose

import (
	"github.com/luraproject/lura/v2/config"
)

const redirectKey = "redirect_on_unauth_to"

func ExtractRedirectUrl(cfg *config.EndpointConfig) (string, bool) {
	if c, ok := cfg.ExtraConfig[ValidatorNamespace]; ok {
		if m, ok := c.(map[string]interface{}); ok {
			if v, ok := m[redirectKey]; ok {
				if s, ok := v.(string); ok {
					return s, true
				}
			}
		}
	}
	return "", false
}
