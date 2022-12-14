package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
)

const TrivyBin = "trivy"

func TrivyDownloadDb(ctx context.Context, dir string) error {
	_, err := trivyCmd(ctx, dir, "-q", "image", "--download-db-only")
	return err
}

func TrivyImage(ctx context.Context, dir string, image string) (*types.Report, error) {
	out, err := trivyCmd(ctx, dir, "-q", "image", "--skip-db-update", "--security-checks", "vuln", "--format", "json", image)
	if err != nil {
		return nil, err
	}
	report := types.Report{}
	err = json.Unmarshal(out, &report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func trivyCmd(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, TrivyBin, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("trivy command %s failed: %w\n%s", strings.Join(args, " "), err, output)
	}
	return output, nil
}
