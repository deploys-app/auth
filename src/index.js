import redirect from './redirect'
import callback from './callback'
import revoke from './revoke'
import token from './token'
import info from './info'

/**
 * @typedef Env
 * @property {import('@cloudflare/workers-types').D1Database} DB
 * @property {import('@cloudflare/workers-types').Hyperdrive} HYPERDRIVE
 * @property {string} OAUTH2_CLIENT_ID
 * @property {string} OAUTH2_CLIENT_SECRET
 */

export default {
	/**
	 * @param {import('@cloudflare/workers-types').Request} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 **/
	async fetch (request, env, ctx) {
		const url = new URL(request.url)

		switch (url.pathname) {
		case '/info':
			return info(request, env, ctx)
		case '/':
			return redirect(request, env, ctx)
		case '/callback':
			return callback(request, env, ctx)
		case '/revoke':
			return revoke(request, env, ctx)
		case '/token':
			return token(request, env, ctx)
		default:
			return new Response('404 page not found', { status: 404 })
		}
	},
	/**
	 * @param {import('@cloudflare/workers-types').ScheduledEvent} event
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<void>}
	 */
	async scheduled (event, env, ctx) {
		const job = env.DB.batch([
			// clear expired sessions
			env.DB.prepare(`
				delete from sessions
				where current_timestamp > datetime(created_at, '+1 hour')
			`),
			// clear expired oauth2 codes
			env.DB.prepare(`
				delete from oauth2_codes
				where current_timestamp > datetime(created_at, '+1 hour')
			`),
			// delete expired tokens
			env.DB.prepare(`
				delete from tokens
				where current_timestamp > expires_at
			`)
		])
		ctx.waitUntil(job)
	}
}
