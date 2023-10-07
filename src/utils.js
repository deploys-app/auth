export async function hash (token) {
	const digest = await crypto.subtle.digest({ name: 'SHA-256' }, new TextEncoder().encode(token))
	return toRawURLEncoding(btoa(String.fromCodePoint(...new Uint8Array(digest))))
}

export function generateToken () {
	const token = new Uint8Array(32)
	crypto.getRandomValues(token)
	return 'deploys-api.' + toRawURLEncoding(btoa(String.fromCodePoint(...token)))
}

export function generateState () {
	const state = new Uint8Array(16)
	crypto.getRandomValues(state)
	return Array.from(state, (x) => x.toString(16).padStart(2, '0')).join('')
}

export function generateSessionId () {
	const sessionId = new Uint8Array(32)
	crypto.getRandomValues(sessionId)
	return Array.from(sessionId, (x) => x.toString(16).padStart(2, '0')).join('')
}

/**
 * isUrl checks if a string is a valid URL
 * @param {string} s
 * @returns {boolean}
 */
export function isUrl (s) {
	try {
		const u = new URL(s)
		return (u.protocol === 'http:' || u.protocol === 'https:') && u.host
	} catch (e) {
		return false
	}
}


function toRawURLEncoding (s) {
	return s.replace(/=*$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}
