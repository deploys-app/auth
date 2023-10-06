export async function hash (token) {
	const digest = await crypto.subtle.digest({ name: 'SHA-256' }, new TextEncoder().encode(token))
	return toRawURLEncoding(btoa(String.fromCodePoint(...new Uint8Array(digest))))
}

export function generate () {
	const token = new Uint8Array(32)
	crypto.getRandomValues(token)
	return 'deploys-api.' + toRawURLEncoding(btoa(String.fromCodePoint(...token)))
}

function toRawURLEncoding (s) {
	return s.replace(/=*$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}
