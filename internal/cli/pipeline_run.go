package cli

import (
	"context"

	"github.com/posener/complete"

	"github.com/hashicorp/waypoint-plugin-sdk/terminal"
	clientpkg "github.com/hashicorp/waypoint/internal/client"
	"github.com/hashicorp/waypoint/internal/clierrors"
	jobstream "github.com/hashicorp/waypoint/internal/jobstream"
	"github.com/hashicorp/waypoint/internal/pkg/flag"
	pb "github.com/hashicorp/waypoint/pkg/server/gen"
)

type PipelineRunCommand struct {
	*baseCommand

	flagPipelineId string
}

func (c *PipelineRunCommand) Run(args []string) int {
	// Initialize. If we fail, we just exit since Init handles the UI.
	if err := c.Init(
		WithArgs(args),
		WithFlags(c.Flags()),
	); err != nil {
		return 1
	}

	var pipelineName string
	if len(c.args) == 0 && c.flagPipelineId == "" {
		c.ui.Output("Pipeline name or ID required.\n\n%s", c.Help(), terminal.WithErrorStyle())
		return 1
	} else if c.flagPipelineId == "" {
		pipelineName = c.args[0]
	} else {
		c.ui.Output("Both pipeline name and ID were specified, using pipeline ID", terminal.WithWarningStyle())
	}

	err := c.DoApp(c.Ctx, func(ctx context.Context, app *clientpkg.App) error {
		// setup pipeline name to be used for UI printing
		pipelineIdent := pipelineName
		if c.flagPipelineId != "" {
			pipelineIdent = c.flagPipelineId
		}

		app.UI.Output("Running pipeline %q for application %q",
			pipelineIdent, app.Ref().Application, terminal.WithHeaderStyle())

		sg := app.UI.StepGroup()
		defer sg.Wait()

		step := sg.Add("Building pipeline execution request...")
		defer step.Abort()

		// build the initial job template for running the pipeline
		runJobTemplate := &pb.Job{
			Application:  app.Ref(),
			Workspace:    c.project.WorkspaceRef(),
			TargetRunner: &pb.Ref_Runner{Target: &pb.Ref_Runner_Any{}},
		}

		// build the base api request
		runPipelineReq := &pb.RunPipelineRequest{
			JobTemplate: runJobTemplate,
		}

		// Reference by ID if set, otherwise by name
		if c.flagPipelineId != "" {
			runPipelineReq.Pipeline = &pb.Ref_Pipeline{
				Ref: &pb.Ref_Pipeline_Id{
					Id: &pb.Ref_PipelineId{
						Id: c.flagPipelineId,
					},
				},
			}
		} else {
			runPipelineReq.Pipeline = &pb.Ref_Pipeline{
				Ref: &pb.Ref_Pipeline_Owner{
					Owner: &pb.Ref_PipelineOwner{
						Project:      &pb.Ref_Project{Project: app.Ref().Project},
						PipelineName: pipelineName,
					},
				},
			}
		}

		step.Update("Requesting to queue run of pipeline %q...", pipelineIdent)

		// take pipeline id and queue a RunPipeline with a Job Template.
		resp, err := c.project.Client().RunPipeline(c.Ctx, runPipelineReq)
		if err != nil {
			return err
		}

		step.Update("Pipeline %q has started running. Attempting to read job stream sequentially in order", pipelineIdent)

		steps := len(resp.JobMap)
		step.Update("%d steps detected, run sequence %d", steps, resp.Sequence)
		step.Done()

		// Receive job ids from running pipeline, use job client to attach to job stream
		// and stream here. First pass can be linear job streaming
		successful := steps
		for _, jobId := range resp.AllJobIds {
			app.UI.Output("Executing Step %q", resp.JobMap[jobId].Step, terminal.WithHeaderStyle())
			app.UI.Output("Reading job stream (jobId: %s)...", jobId, terminal.WithInfoStyle())
			app.UI.Output("")

			result, err := jobstream.Stream(c.Ctx, jobId,
				jobstream.WithClient(c.project.Client()),
				jobstream.WithUI(app.UI))
			if err != nil {
				return err
			}

			var state pb.Status_State
			if result.Build != nil {
				state = result.Build.Build.Status.State
			} else if result.Deploy != nil {
				state = result.Deploy.Deployment.Status.State
			} else if result.Release != nil {
				state = result.Deploy.Deployment.Status.State
			}
			if state != pb.Status_SUCCESS {
				successful--
			}
		}

		app.UI.Output("✔ Pipeline %q (%s) finished! %d/%d steps successfully completed.", pipelineIdent, app.Ref().Project, successful, steps, terminal.WithSuccessStyle())

		return nil
	})
	if err != nil {
		c.ui.Output(clierrors.Humanize(err), terminal.WithErrorStyle())
		return 1
	}

	return 0
}

func (c *PipelineRunCommand) Flags() *flag.Sets {
	return c.flagSet(flagSetOperation, func(set *flag.Sets) {
		f := set.NewSet("Command Options")
		f.StringVar(&flag.StringVar{
			Name:    "id",
			Target:  &c.flagPipelineId,
			Default: "",
			Usage:   "Run a pipeline by ID.",
		})
	})
}

func (c *PipelineRunCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *PipelineRunCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PipelineRunCommand) Synopsis() string {
	return "Manually execute a pipeline by name."
}

func (c *PipelineRunCommand) Help() string {
	return formatHelp(`
Usage: waypoint pipeline run [options] <pipeline-name>

  Run a pipeline by name. If run outside of a project dir, a '-project' flag is
	required.

` + c.Flags().Help())
}
