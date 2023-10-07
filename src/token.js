/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<Response>}
 **/
export default async function (request, env, ctx) {
	if (request.method !== 'POST') {
		return new Response('Method not allowed', { status: 405 })
	}

	const f = await request.formData()
	const code = f.get('code') || ''
	if (!code) {
		return new Response('Missing code parameter', { status: 400 })
	}

	return new Response(JSON.stringify({
		refresh_token: code,
		token_type: 'Bearer',
	}), {
		headers: {
			'content-type': 'application/json'
		}
	})
}
