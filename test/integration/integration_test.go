package integration

import (
	"context"
	"os"
	"testing"

	"github.com/cucumber/godog"
)

func TestFeatures(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration tests. Set INTEGRATION_TEST=1 to run.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize test containers
	tc, err := NewTestContext(ctx)
	if err != nil {
		t.Fatalf("Failed to create test context: %v", err)
	}
	defer tc.Close(ctx)

	// Run godog test suite
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			steps := NewStepsContext(tc)
			steps.RegisterSteps(sc)
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("Non-zero status returned, failed to run feature tests")
	}
}
