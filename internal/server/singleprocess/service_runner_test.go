package singleprocess

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hashicorp/waypoint/internal/server"
	pb "github.com/hashicorp/waypoint/internal/server/gen"
	serverptypes "github.com/hashicorp/waypoint/internal/server/ptypes"
)

// Test the happy path of getting a runner token
func TestServiceRunnerToken_happy(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Get the runner id
	id, err := server.Id()
	require.NoError(err)
	r := &pb.Runner{
		Id: id,
		Kind: &pb.Runner_Remote_{
			Remote: &pb.Runner_Remote{},
		},
	}

	// Reconnect with no token
	anonClient := server.TestServer(t, impl, server.TestWithToken(""))

	// Start getting the resp
	var resp *pb.RunnerTokenResponse
	var respErr error
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		resp, respErr = anonClient.RunnerToken(ctx, &pb.RunnerTokenRequest{
			Runner: r,
		})
	}()

	// Should block
	select {
	case <-time.After(50 * time.Millisecond):
	case <-doneCh:
		t.Fatal("should block")
	}

	// Adopt it
	_, err = client.AdoptRunner(ctx, &pb.AdoptRunnerRequest{
		RunnerId: id,
		Adopt:    true,
	})
	require.NoError(err)

	// Should be done
	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		t.Fatal("should return")
	}

	// Verify token resp
	require.NoError(respErr)
	require.NotNil(resp)
	require.NotEmpty(resp.Token)

	// Reconnect with the token
	client = server.TestServer(t, impl, server.TestWithToken(resp.Token))

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: r,
			},
		},
	}))

	// Wait for first message to confirm we're registered
	{
		resp, err := stream.Recv()
		require.NoError(err)
		require.NotNil(resp.Config)
		require.Empty(resp.Config.ConfigVars)
	}

	// Get and list the runner
	{
		runner, err := client.GetRunner(ctx, &pb.GetRunnerRequest{RunnerId: id})
		require.NoError(err)
		require.NotNil(runner)
		require.Equal(runner.Id, id)
		require.Equal(pb.Runner_ADOPTED, runner.AdoptionState)

		runners, err := client.ListRunners(ctx, &pb.ListRunnersRequest{})
		require.NoError(err)
		require.Len(runners.Runners, 1)
		require.Equal(runners.Runners[0].Id, id)
	}

	// Re-requesting a token should fail immediately. Because the runner is
	// adopted, a second token request should fail; we expect the runner to
	// already have the token.
	{
		resp, err := anonClient.RunnerToken(ctx, &pb.RunnerTokenRequest{
			Runner: r,
		})
		require.Error(err)
		require.Nil(resp)
	}

}

// Test that an explicitly rejected runner can't do anything
func TestServiceRunnerToken_reject(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Get the runner id
	id, err := server.Id()
	require.NoError(err)
	r := &pb.Runner{
		Id: id,
		Kind: &pb.Runner_Remote_{
			Remote: &pb.Runner_Remote{},
		},
	}

	// Reconnect with no token
	anonClient := server.TestServer(t, impl, server.TestWithToken(""))

	// Start getting the resp
	var respErr error
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		_, respErr = anonClient.RunnerToken(ctx, &pb.RunnerTokenRequest{
			Runner: r,
		})
	}()

	// Should block
	select {
	case <-time.After(50 * time.Millisecond):
	case <-doneCh:
		t.Fatal("should block")
	}

	// Adopt it
	_, err = client.AdoptRunner(ctx, &pb.AdoptRunnerRequest{
		RunnerId: id,
		Adopt:    false,
	})
	require.NoError(err)

	// Should be done
	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		t.Fatal("should return")
	}

	// Verify token resp
	require.Error(respErr)
	require.Equal(codes.PermissionDenied, status.Code(respErr))

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: r,
			},
		},
	}))

	// Wait for first message to confirm we're registered
	{
		resp, err := stream.Recv()
		require.Error(err)
		require.Equal(codes.PermissionDenied, status.Code(respErr))
		require.Nil(resp)
	}

	// Get and list the runner
	{
		runner, err := client.GetRunner(ctx, &pb.GetRunnerRequest{RunnerId: id})
		require.NoError(err)
		require.NotNil(runner)
		require.Equal(runner.Id, id)
		require.Equal(pb.Runner_REJECTED, runner.AdoptionState)

		runners, err := client.ListRunners(ctx, &pb.ListRunnersRequest{})
		require.NoError(err)
		require.Len(runners.Runners, 1)
		require.Equal(runners.Runners[0].Id, id)
	}
}

// Complete happy path runner config stream
func TestServiceRunnerConfig_happy(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Initialize our app
	TestApp(t, client, serverptypes.TestJobNew(t, nil).Application)

	// Get the runner
	id, err := server.Id()
	require.NoError(err)

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: &pb.Runner{Id: id},
			},
		},
	}))

	// Wait for first message to confirm we're registered
	resp, err := stream.Recv()
	require.NoError(err)
	require.NotNil(resp.Config)
	require.Empty(resp.Config.ConfigVars)

	// Get and list the runner
	{
		runner, err := client.GetRunner(ctx, &pb.GetRunnerRequest{RunnerId: id})
		require.NoError(err)
		require.NotNil(runner)
		require.Equal(runner.Id, id)
		require.Equal(pb.Runner_PREADOPTED, runner.AdoptionState)

		runners, err := client.ListRunners(ctx, &pb.ListRunnersRequest{})
		require.NoError(err)
		require.Len(runners.Runners, 1)
		require.Equal(runners.Runners[0].Id, id)
	}
}

// Test runnerconfig with a premade runner token.
func TestServiceRunnerConfig_preadopt(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Initialize our app
	TestApp(t, client, serverptypes.TestJobNew(t, nil).Application)

	// Get the runner
	id, err := server.Id()
	require.NoError(err)

	// Reconnect with a runner token
	tok, err := testServiceImpl(impl).newToken(0, DefaultKeyId, nil, &pb.Token{
		Kind: &pb.Token_Runner_{
			Runner: &pb.Token_Runner{
				Id: "",
			},
		},
	})
	require.NoError(err)
	client = server.TestServer(t, impl, server.TestWithToken(tok))

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: &pb.Runner{Id: id},
			},
		},
	}))

	// Wait for first message to confirm we're registered
	resp, err := stream.Recv()
	require.NoError(err)
	require.NotNil(resp.Config)
	require.Empty(resp.Config.ConfigVars)

	// Get and list the runner
	{
		runner, err := client.GetRunner(ctx, &pb.GetRunnerRequest{RunnerId: id})
		require.NoError(err)
		require.NotNil(runner)
		require.Equal(runner.Id, id)
		require.Equal(pb.Runner_PREADOPTED, runner.AdoptionState)

		runners, err := client.ListRunners(ctx, &pb.ListRunnersRequest{})
		require.NoError(err)
		require.Len(runners.Runners, 1)
		require.Equal(runners.Runners[0].Id, id)
	}
}

// Test runnerconfig with a premade runner token with the wrong ID.
func TestServiceRunnerConfig_preadoptWrongId(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Initialize our app
	TestApp(t, client, serverptypes.TestJobNew(t, nil).Application)

	// Get the runner
	id, err := server.Id()
	require.NoError(err)

	// Reconnect with a runner token
	tok, err := testServiceImpl(impl).newToken(0, DefaultKeyId, nil, &pb.Token{
		Kind: &pb.Token_Runner_{
			Runner: &pb.Token_Runner{
				Id: "hello",
			},
		},
	})
	require.NoError(err)
	client = server.TestServer(t, impl, server.TestWithToken(tok))

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: &pb.Runner{Id: id},
			},
		},
	}))

	// Confirm we're rejected
	_, err = stream.Recv()
	require.Error(err)
	require.Equal(codes.PermissionDenied, status.Code(err))
}

// ODR with no job is not allowed
func TestServiceRunnerConfig_odrNoJob(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Get the runner
	id, err := server.Id()
	require.NoError(err)

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: &pb.Runner{
					Id:   id,
					Kind: &pb.Runner_Odr{Odr: &pb.Runner_ODR{ProfileId: "test-profile"}},
				},
			},
		},
	}))

	// Wait for first message to confirm we're registered
	resp, err := stream.Recv()
	require.Error(err)
	require.Nil(resp)
	require.Equal(codes.FailedPrecondition, status.Code(err))
}

// Test we get our scoped config with ODR set
func TestServiceRunnerConfig_odrScopedConfig(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Get the runner
	id, err := server.Id()
	require.NoError(err)

	// Initialize our app
	app := &pb.Ref_Application{
		Application: "bob",
		Project:     "alice",
	}
	ws := &pb.Ref_Workspace{Workspace: "dev"}

	// Set some config before the project, runner, anything is configured.
	{
		resp, err := client.SetConfig(ctx, &pb.ConfigSetRequest{Variables: []*pb.ConfigVar{
			// Global non-runner, should NOT appear
			{
				Target: &pb.ConfigVar_Target{
					AppScope: &pb.ConfigVar_Target_Global{
						Global: &pb.Ref_Global{},
					},
				},

				Name:  "global",
				Value: &pb.ConfigVar_Static{Static: "value"},
			},

			// Global runner
			{
				Target: &pb.ConfigVar_Target{
					AppScope: &pb.ConfigVar_Target_Global{
						Global: &pb.Ref_Global{},
					},

					Runner: &pb.Ref_Runner{
						Target: &pb.Ref_Runner_Any{
							Any: &pb.Ref_RunnerAny{},
						},
					},
				},

				Name:  "global-runner",
				Value: &pb.ConfigVar_Static{Static: "value"},
			},

			// Project-scoped
			{
				Target: &pb.ConfigVar_Target{
					AppScope: &pb.ConfigVar_Target_Project{
						Project: &pb.Ref_Project{
							// Does NOT match
							Project: "nottheoneyouwant",
						},
					},

					Runner: &pb.Ref_Runner{
						Target: &pb.Ref_Runner_Any{
							Any: &pb.Ref_RunnerAny{},
						},
					},
				},

				Name:  "pNo",
				Value: &pb.ConfigVar_Static{Static: "value"},
			},
			{
				Target: &pb.ConfigVar_Target{
					AppScope: &pb.ConfigVar_Target_Project{
						Project: &pb.Ref_Project{
							Project: app.Project,
						},
					},

					Runner: &pb.Ref_Runner{
						Target: &pb.Ref_Runner_Any{
							Any: &pb.Ref_RunnerAny{},
						},
					},
				},

				Name:  "pYes",
				Value: &pb.ConfigVar_Static{Static: "value"},
			},
		}})
		require.NoError(err)
		require.NotNil(resp)
	}

	// Create a job
	TestApp(t, client, app)
	queueResp, err := client.QueueJob(ctx, &pb.QueueJobRequest{Job: serverptypes.TestJobNew(t, &pb.Job{
		Application: app,
		Workspace:   ws,
		Labels:      map[string]string{"env": "dev"},
		TargetRunner: &pb.Ref_Runner{
			Target: &pb.Ref_Runner_Id{
				Id: &pb.Ref_RunnerId{
					Id: id,
				},
			},
		},
	})})
	require.NoError(err)
	require.NotNil(queueResp)
	require.NotEmpty(queueResp.JobId)

	// Open the config stream
	stream, err := client.RunnerConfig(ctx)
	require.NoError(err)
	defer stream.CloseSend()

	// Register
	require.NoError(stream.Send(&pb.RunnerConfigRequest{
		Event: &pb.RunnerConfigRequest_Open_{
			Open: &pb.RunnerConfigRequest_Open{
				Runner: &pb.Runner{
					Id:   id,
					Kind: &pb.Runner_Odr{Odr: &pb.Runner_ODR{ProfileId: "test-profile"}},
				},
			},
		},
	}))

	// Wait for first message to confirm we're registered
	resp, err := stream.Recv()
	require.NoError(err)
	require.NotNil(resp)

	// Test our vars
	vars := resp.Config.ConfigVars
	require.NotEmpty(vars)
	var keys []string
	for _, v := range vars {
		keys = append(keys, v.Name)
	}
	require.Equal(keys, []string{"global-runner", "pYes"})
}

// Complete happy path job stream
func TestServiceRunnerJobStream_complete(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Initialize our app
	TestApp(t, client, serverptypes.TestJobNew(t, nil).Application)

	// Create a job
	queueResp, err := client.QueueJob(ctx, &pb.QueueJobRequest{Job: serverptypes.TestJobNew(t, nil)})
	require.NoError(err)
	require.NotNil(queueResp)
	require.NotEmpty(queueResp.JobId)

	// Register our runner
	id, _ := TestRunner(t, client, nil)

	// Start a job request
	stream, err := client.RunnerJobStream(ctx)
	require.NoError(err)
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Request_{
			Request: &pb.RunnerJobStreamRequest_Request{
				RunnerId: id,
			},
		},
	}))

	// Wait for assignment and ack
	{
		resp, err := stream.Recv()
		require.NoError(err)
		assignment, ok := resp.Event.(*pb.RunnerJobStreamResponse_Assignment)
		require.True(ok, "should be an assignment")
		require.NotNil(assignment)
		require.Equal(queueResp.JobId, assignment.Assignment.Job.Id)

		require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
			Event: &pb.RunnerJobStreamRequest_Ack_{
				Ack: &pb.RunnerJobStreamRequest_Ack{},
			},
		}))
	}

	// Send download info
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Download{
			Download: &pb.GetJobStreamResponse_Download{
				DataSourceRef: &pb.Job_DataSource_Ref{
					Ref: &pb.Job_DataSource_Ref_Git{
						Git: &pb.Job_Git_Ref{
							Commit: "hello",
						},
					},
				},
			},
		},
	}))

	// Complete the job
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Complete_{
			Complete: &pb.RunnerJobStreamRequest_Complete{},
		},
	}))

	// Should be done
	_, err = stream.Recv()
	require.Error(err)
	require.Equal(io.EOF, err)

	// Query our job and it should be done
	job, err := testServiceImpl(impl).state.JobById(queueResp.JobId, nil)
	require.NoError(err)
	require.Equal(pb.Job_SUCCESS, job.State)

	// It should store the state
	require.NotNil(job.DataSourceRef)
	ref := job.DataSourceRef.Ref.(*pb.Job_DataSource_Ref_Git).Git
	require.Equal("hello", ref.Commit)

	// Verify that we update the project last data ref
	{
		ws, err := testServiceImpl(impl).state.WorkspaceGet(job.Workspace.Workspace)
		require.NoError(err)
		require.NotNil(ws)
		require.Len(ws.Projects, 1)
		require.Equal("hello", ws.Projects[0].DataSourceRef.Ref.(*pb.Job_DataSource_Ref_Git).Git.Commit)
	}
}

func TestServiceRunnerJobStream_badOpen(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Start exec with a bad starting message
	stream, err := client.RunnerJobStream(ctx)
	require.NoError(err)
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Ack_{
			Ack: &pb.RunnerJobStreamRequest_Ack{},
		},
	}))

	// Wait for data
	resp, err := stream.Recv()
	require.Error(err)
	require.Equal(codes.FailedPrecondition, status.Code(err))
	require.Nil(resp)
}

func TestServiceRunnerJobStream_errorBeforeAck(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Initialize our app
	TestApp(t, client, serverptypes.TestJobNew(t, nil).Application)

	// Create a job
	queueResp, err := client.QueueJob(ctx, &pb.QueueJobRequest{Job: serverptypes.TestJobNew(t, nil)})
	require.NoError(err)
	require.NotNil(queueResp)
	require.NotEmpty(queueResp.JobId)

	// Register our runner
	id, _ := TestRunner(t, client, nil)

	// Start a job request
	stream, err := client.RunnerJobStream(ctx)
	require.NoError(err)
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Request_{
			Request: &pb.RunnerJobStreamRequest_Request{
				RunnerId: id,
			},
		},
	}))

	// Wait for assignment and DONT ack, send an error instead
	{
		resp, err := stream.Recv()
		require.NoError(err)
		assignment, ok := resp.Event.(*pb.RunnerJobStreamResponse_Assignment)
		require.True(ok, "should be an assignment")
		require.NotNil(assignment)
		require.Equal(queueResp.JobId, assignment.Assignment.Job.Id)

		require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
			Event: &pb.RunnerJobStreamRequest_Error_{
				Error: &pb.RunnerJobStreamRequest_Error{
					Error: status.Newf(codes.Unknown, "error").Proto(),
				},
			},
		}))
	}

	// Should be done
	_, err = stream.Recv()
	require.Error(err)
	require.Equal(io.EOF, err)

	// Query our job and it should be queued again
	job, err := testServiceImpl(impl).state.JobById(queueResp.JobId, nil)
	require.NoError(err)
	require.Equal(pb.Job_QUEUED, job.State)
}

// Complete happy path job stream
func TestServiceRunnerJobStream_cancel(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	// Create our server
	impl, err := New(WithDB(testDB(t)))
	require.NoError(err)
	client := server.TestServer(t, impl)

	// Initialize our app
	TestApp(t, client, serverptypes.TestJobNew(t, nil).Application)

	// Create a job
	queueResp, err := client.QueueJob(ctx, &pb.QueueJobRequest{Job: serverptypes.TestJobNew(t, nil)})
	require.NoError(err)
	require.NotNil(queueResp)
	require.NotEmpty(queueResp.JobId)

	// Register our runner
	id, _ := TestRunner(t, client, nil)

	// Start a job request
	stream, err := client.RunnerJobStream(ctx)
	require.NoError(err)
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Request_{
			Request: &pb.RunnerJobStreamRequest_Request{
				RunnerId: id,
			},
		},
	}))

	// Wait for assignment and ack
	{
		resp, err := stream.Recv()
		require.NoError(err)
		assignment, ok := resp.Event.(*pb.RunnerJobStreamResponse_Assignment)
		require.True(ok, "should be an assignment")
		require.NotNil(assignment)
		require.Equal(queueResp.JobId, assignment.Assignment.Job.Id)

		require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
			Event: &pb.RunnerJobStreamRequest_Ack_{
				Ack: &pb.RunnerJobStreamRequest_Ack{},
			},
		}))
	}

	// Cancel the job
	_, err = client.CancelJob(ctx, &pb.CancelJobRequest{JobId: queueResp.JobId})
	require.NoError(err)

	// Wait for the cancel event
	{
		resp, err := stream.Recv()
		require.NoError(err)
		_, ok := resp.Event.(*pb.RunnerJobStreamResponse_Cancel)
		require.True(ok, "should be an assignment")
	}

	// Complete the job
	require.NoError(stream.Send(&pb.RunnerJobStreamRequest{
		Event: &pb.RunnerJobStreamRequest_Complete_{
			Complete: &pb.RunnerJobStreamRequest_Complete{},
		},
	}))

	// Should be done
	resp, err := stream.Recv()
	if err == nil && resp != nil {
		t.Logf("response type (should've been nil): %#v", resp.Event)
	}
	require.Error(err)
	require.Equal(io.EOF, err, err.Error())

	// Query our job and it should be done
	job, err := testServiceImpl(impl).state.JobById(queueResp.JobId, nil)
	require.NoError(err)
	require.Equal(pb.Job_SUCCESS, job.State)
	require.NotEmpty(job.CancelTime)
}

func TestServiceRunnerGetDeploymentConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("with no server config", func(t *testing.T) {
		require := require.New(t)

		// Create our server
		impl, err := New(WithDB(testDB(t)))
		require.NoError(err)
		client := server.TestServer(t, impl)

		// Request deployment config
		resp, err := client.RunnerGetDeploymentConfig(ctx, &pb.RunnerGetDeploymentConfigRequest{})
		require.NoError(err)
		require.Empty(resp.ServerAddr)
	})

	t.Run("with server config", func(t *testing.T) {
		require := require.New(t)

		// Create our server
		impl, err := New(WithDB(testDB(t)))
		require.NoError(err)
		client := server.TestServer(t, impl)

		// Set some config
		_, err = client.SetServerConfig(ctx, &pb.SetServerConfigRequest{
			Config: serverptypes.TestServerConfig(t, nil),
		})
		require.NoError(err)

		// Request deployment config
		resp, err := client.RunnerGetDeploymentConfig(ctx, &pb.RunnerGetDeploymentConfigRequest{})
		require.NoError(err)
		require.NotEmpty(resp.ServerAddr)
	})
}
