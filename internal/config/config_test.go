package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad_compare(t *testing.T) {
	cases := []struct {
		File string
		Err  string
		Func func(*testing.T, *Config)
	}{
		{
			"project.hcl",
			"",
			func(t *testing.T, c *Config) {
				require.Equal(t, "hello", c.Project)
			},
		},

		{
			"project_pwd.hcl",
			"",
			func(t *testing.T, c *Config) {
				require.NotEmpty(t, c.Project)
			},
		},

		{
			"project_path_project.hcl",
			"",
			func(t *testing.T, c *Config) {
				expected, err := filepath.Abs(filepath.Join("testdata", "compare"))
				require.NoError(t, err)
				require.Equal(t, expected, c.Project)
			},
		},

		{
			"project_function.hcl",
			"",
			func(t *testing.T, c *Config) {
				require.Equal(t, "HELLO", c.Project)
			},
		},

		{
			"project_static_config.hcl",
			"",
			func (t *testing.T, c *Config){
				require.Equal(t, "hello", c.Project)
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.File, func(t *testing.T) {
			r := require.New(t)

			cfg, err := Load(filepath.Join("testdata", "compare", tt.File), nil)
			if tt.Err != "" {
				r.Error(err)
				r.Contains(err.Error(), tt.Err)
				return
			}
			r.NoError(err)

			tt.Func(t, cfg)
		})
	}
}
