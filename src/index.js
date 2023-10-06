import redirect from './redirect'
import callback from './callback'
import revoke from './revoke'

export default {
	async fetch (request, env, ctx) {
		const url = new URL(request.url)

		switch (url.pathname) {
			case '/':
				return redirect(request, env, ctx)
			case '/callback':
				return callback(request, env, ctx)
			case '/revoke':
				return revoke(request, env, ctx)
			default:
				return new Response('404 page not found', { status: 404 })
		}
	},
	async scheduled (event, env, ctx) {
		const job = env.DB
			.prepare(`
                delete
                from sessions
                where created_at > datetime(current_timestamp, '+1 hour')
			`)
			.run()

		ctx.waitUntil(job)
	}
}
