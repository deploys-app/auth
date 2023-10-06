import { Client } from 'pg'
import { hash } from './token'

const landing = 'https://www.deploys.app/'

export default async function (request, env, ctx) {
	const url = new URL(request.url)
	const token = url.searchParams.get('token')
	const callback = url.searchParams.get('callback') || landing

	if (token) {
		try {
			const client = new Client({ connectionString: env.HYPERDRIVE.connectionString })
			await client.connect()
			const hashedToken = await hash(token)
			await client.query(`
                delete
                from user_tokens
                where token = $1
			`, [hashedToken])
		} catch (e) {
			console.log('delete token error:', e)
			return new Response('Cloudflare HyperDrive Error, please try again...', { status: 500 })
		}
	}

	return Response.redirect(callback, 302)
}
