import moment, { type Moment } from "moment";
import { requestUrl } from "obsidian";
import {generateRandomKey, masterKeyToString, encryptString, encryptArrayBuffer} from "./crypto/crypto";

type ShareNoteOptions = {
	title?: string;
};

type JsonPayload = {
	body: string;
	title?: string;
	metadata?: Record<string, unknown>;
};

type Response = {
	view_url: string;
	expire_time: Moment;
	secret_token: string;
	note_id: string;
};

export class NoteSharingService {
	private _url: string;
	private _userId: string;
	private _pluginVersion: string;

	constructor(serverUrl: string, userId: string, pluginVersion: string) {
		this.serverUrl = serverUrl;
		this._userId = userId;
		this._pluginVersion = pluginVersion;
	}

	/**
	 * @param body Markdown file to share.
	 * @returns link to shared note with attached decryption key.
	 */
	public async shareNote(
		body: string,
		embededFiles: {original: string, data: ArrayBuffer}[],
		options?: ShareNoteOptions
	): Promise<Response> {
		body = this.sanitizeNote(body);

		const jsonPayload: JsonPayload = {
			body: body,
			title: options?.title,
		};

		const stringPayload = JSON.stringify(jsonPayload);

		const key = await generateRandomKey();
		const secret = masterKeyToString(key);

		const ciphertext = await encryptString(stringPayload, key);

		const embeded: { original: string; base64: string }[] = [];
		for (const embed of embededFiles) {
			const data = embed.data;
			const base64 = await encryptArrayBuffer(data, key);
			embeded.push({ original: embed.original, base64 });
		}

		const res = await this.postNote(ciphertext, secret.iv, embeded);
		res.view_url += `#${secret.key}`;
		console.log(`Note shared: ${res.view_url}`);
		return res;
	}

	public async deleteNote(
		noteId: string,
		secretToken: string
	): Promise<void> {
		await requestUrl({
			url: `${this._url}/api/note/${noteId}`,
			method: "DELETE",
			contentType: "application/json",
			body: JSON.stringify({
				user_id: this._userId,
				secret_token: secretToken,
			}),
		});
	}

	private async postNote(ciphertext: string, iv: string, embededFiles: { original: string; base64: string }[]): Promise<Response> {
		const res = await requestUrl({
			url: `${this._url}/api/note`,
			method: "POST",
			contentType: "application/json",
			body: JSON.stringify({
				ciphertext: ciphertext,
				iv: iv,
				user_id: this._userId,
				plugin_version: this._pluginVersion,
				crypto_version: "v3",
				embeded: embededFiles,
			}),
		});

		if (res.status == 200 && res.json != null) {
			const returnValue = res.json;
			returnValue.expire_time = moment(returnValue.expire_time);
			return <Response>returnValue;
		}
		throw Error(
			`Error uploading encrypted note (${res.status}): ${res.text}`
		);
	}

	private sanitizeNote(mdText: string): string {
		mdText = mdText.trim();
		const match = mdText.match(
			/^(?:---\s*\n)(?:(?:.*?\n)*?)(?:---)((?:.|\n|\r)*)/
		);
		if (match) {
			mdText = match[1].trim();
		}
		return mdText;
	}

	public set serverUrl(newUrl: string) {
		newUrl = newUrl.replace(/([^:]\/)\/+/g, "$1");
		if (newUrl[newUrl.length - 1] == "/") {
			newUrl = newUrl.substring(0, newUrl.length - 1);
		}
		this._url = newUrl;
	}
}
