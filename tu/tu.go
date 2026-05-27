// Package tu is the test utility for spinning up an isolated CockroachDB.
package tu

import (
	"context"
	"database/sql"

	"github.com/acoshift/pgsql/pgctx"
	"github.com/cockroachdb/cockroach-go/v2/testserver"

	"github.com/deploys-app/auth/schema"
)

// Context holds the test server and DB connection.
type Context struct {
	ts testserver.TestServer
	DB *sql.DB
}

func (c *Context) setup() {
	var err error
	defer func() {
		if err != nil {
			panic(err)
		}
	}()

	c.ts, err = testserver.NewTestServer()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			c.Teardown()
		}
	}()

	c.DB, err = sql.Open("postgres", c.ts.PGURL().String()+"&enable_implicit_transaction_for_batch_statements=off")
	if err != nil {
		return
	}

	err = schema.Migrate(context.Background(), c.DB)
}

func (c *Context) Teardown() {
	if c.DB != nil {
		c.DB.Close()
	}
	if c.ts != nil {
		c.ts.Stop()
	}
}

// Ctx returns a context with the DB injected, the way pgctx.Middleware would.
func (c *Context) Ctx() context.Context {
	return pgctx.NewContext(context.Background(), c.DB)
}

// Setup starts a CockroachDB test server and runs the schema migration.
func Setup() *Context {
	c := &Context{}
	c.setup()
	return c
}
