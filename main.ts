import {
	MarkdownView,
	Menu,
	Notice,
	Plugin,
	TAbstractFile,
	TFile,
	WorkspaceLeaf,
} from "obsidian";
import { NoteSharingService } from "src/NoteSharingService";
import { DEFAULT_SETTINGS } from "src/obsidian/PluginSettings";
import SettingsTab from "src/obsidian/SettingsTab";
import { SharedNoteSuccessModal } from "src/ui/SharedNoteSuccessModal";
import type { EventRef } from "obsidian";
import type { PluginSettings } from "src/obsidian/PluginSettings";
import { useFrontmatterHelper } from "src/obsidian/Frontmatter";
import moment from "moment";
import type { QuickShareCache } from "src/lib/cache/AbstractCache";
import { LocalStorageCache } from "src/lib/cache/LocalStorageCache";
import { FsCache } from "src/lib/cache/FsCache";
import { QuickShareSideView } from "src/ui/QuickShareSideView";
import { writable } from "svelte/store";
import { setActiveMdFile } from "src/lib/stores/ActiveMdFile";

const { subscribe, set: setPluginStore } = writable<NoteSharingPlugin>(null);

export const PluginStore = { subscribe };

export default class NoteSharingPlugin extends Plugin {
	public settings: PluginSettings;
	private noteSharingService: NoteSharingService;
	private cache: QuickShareCache;

	private fileMenuEvent: EventRef;

	async onload() {
		setPluginStore(this);
		await this.loadSettings();

		this.cache = this.settings.useFsCache
			? await new FsCache(this.app).init()
			: await new LocalStorageCache(this.app).init();

		this.noteSharingService = new NoteSharingService(
			this.settings.serverUrl,
			this.settings.anonymousUserId,
			this.manifest.version
		);

		// Init settings tab
		this.addSettingTab(new SettingsTab(this.app, this));

		// Add note sharing command
		this.addCommands();

		// Add event listeners
		this.fileMenuEvent = this.app.workspace.on(
			"file-menu",
			(menu, file, source) => this.onMenuOpenCallback(menu, file, source)
		);
		this.registerEvent(this.fileMenuEvent);

		this.registerEvent(
			this.app.vault.on("rename", (file, oldPath) => {
				if (!this.cache.has(oldPath)) {
					return;
				}
				this.cache.rename(oldPath, file.path);
				console.log("renamed", file.path);
			})
		);

		this.registerEvent(
			this.app.vault.on("delete", (file) => {
				if (!this.cache.has(file.path)) {
					return;
				}
				this.cache.set(file.path, (data) => ({
					...data,
					deleted_from_vault: true,
				}));
				console.log("deleted", file.path);
			})
		);

		this.registerEvent(
			this.app.workspace.on("active-leaf-change", (leaf) => {
				if (leaf.view instanceof MarkdownView) {
					setActiveMdFile(leaf.view.file);
				}
			})
		);

		// Register the sidebar view
		this.registerView(
			QuickShareSideView.viewType,
			(leaf: WorkspaceLeaf) => new QuickShareSideView(leaf)
		);

		// Add the view to the right sidebar
		this.app.workspace.onLayoutReady(this.initLeaf.bind(this));
	}

	async initLeaf() {
		if (
			this.app.workspace.getLeavesOfType(QuickShareSideView.viewType)
				.length
		) {
			return;
		}
		await this.app.workspace.getRightLeaf(false).setViewState({
			type: QuickShareSideView.viewType,
			active: true,
		});
	}

	onunload() {}

	async loadSettings() {
		this.settings = Object.assign(
			{},
			DEFAULT_SETTINGS,
			await this.loadData()
		);
		await this.saveSettings();
	}

	async saveSettings() {
		await this.saveData(this.settings);
		if (this.noteSharingService) {
			this.noteSharingService.serverUrl = this.settings.serverUrl;
		}
	}

	addCommands() {
		this.addCommand({
			id: "obsidian-quickshare-share-note",
			name: "Create share link",
			checkCallback: (checking: boolean) => {
				// Only works on Markdown views
				const activeView =
					this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!activeView) return false;
				if (checking) return true;
				this.shareNote(activeView.file);
			},
		});

		this.addCommand({
			id: "obsidian-quickshare-delete-note",
			name: "Unshare note",
			checkCallback: (checking: boolean) => {
				// Only works on Markdown views
				const activeView =
					this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!activeView) return false;

				if (
					(checking && !this.cache.has(activeView.file.path)) ||
					this.cache.get(activeView.file.path).deleted_from_server
				) {
					return false;
				}
				if (checking) {
					return true;
				}
				this.deleteNote(activeView.file.path);
			},
		});
	}

	// https://github.dev/platers/obsidian-linter/blob/c30ceb17dcf2c003ca97862d94cbb0fd47b83d52/src/main.ts#L139-L149
	onMenuOpenCallback(menu: Menu, file: TAbstractFile, source: string) {
		if (file instanceof TFile && file.extension === "md") {
			menu.addItem((item) => {
				item.setIcon("paper-plane-glyph");
				item.setTitle("Create share link");
				item.onClick(async (evt) => {
					this.shareNote(file);
				});
			});
		}
	}

	async shareNote(file: TFile) {
		const { setFrontmatterKeys } = useFrontmatterHelper(this.app);

		let body = await this.app.vault.read(file);
		const embeds = this.app.metadataCache.getFileCache(file)?.embeds || [];
		console.log('found embeds', embeds);

		const embededFiles = [];

		for (const embed of embeds) {
			const fileEmbeded = this.app.metadataCache.getFirstLinkpathDest(
				embed.link,
				file.path
			);
			console.log('found embeded file', fileEmbeded);
			if (fileEmbeded.extension.match(/(png|jpe?g|svg|bmp|gif|)$/i)[0]?.length <= 0) {
				console.log('not image, skip');
				continue;
			}
			const data = await this.app.vault.adapter.readBinary(fileEmbeded.path);
			// image to base64 html and replace the link
			const base64 = btoa(
				new Uint8Array(data).reduce(
					(data, byte) => data + String.fromCharCode(byte),
					""
				)
			);
			embededFiles.push({ original: embed.original, base64: base64 });
		}

		const title = this.settings.shareFilenameAsTitle
			? file.basename
			: undefined;

		this.noteSharingService
			.shareNote(body, embededFiles, { title })
			.then((res) => {
				if (this.settings.useFrontmatter) {
					const datetime = moment().format(
						this.settings.frontmatterDateFormat ||
							DEFAULT_SETTINGS.frontmatterDateFormat
					);
					setFrontmatterKeys(file, {
						url: `"${res.view_url}"`,
						datetime: datetime,
					});
				}

				// NOTE: this is an async call, but we don't need to wait for it
				this.cache.set(file.path, {
					shared_datetime: moment().toISOString(),
					updated_datetime: null,
					expire_datetime: res.expire_time.toISOString(),
					view_url: res.view_url,
					secret_token: res.secret_token,
					note_id: res.note_id,
					basename: file.basename,
				});

				new SharedNoteSuccessModal(
					this,
					res.view_url,
					res.expire_time
				).open();
			})
			.catch(this.handleSharingError);
	}

	async deleteNote(fileId: string) {
		const { setFrontmatterKeys } = useFrontmatterHelper(this.app);

		const cacheData = this.cache.get(fileId);

		if (!cacheData) {
			return;
		}

		this.noteSharingService
			.deleteNote(cacheData.note_id, cacheData.secret_token)
			.then(() => {
				this.cache.set(fileId, (data) => ({
					...data,
					deleted_from_server: true,
				}));
				new Notice(`Unshared note: "${cacheData.basename}"`, 7500);
				console.info("Unshared note: ", fileId);

				const _file = this.app.vault
					.getMarkdownFiles()
					.find((f) => f.path === fileId);

				if (!_file) {
					return;
				}

				setFrontmatterKeys(_file, {
					url: `"Removed"`,
					datetime: `"N/A"`,
				});
			})
			.catch(this.handleSharingError);
	}

	public set $cache(cache: QuickShareCache) {
		this.cache = cache;
	}

	public get $cache() {
		return this.cache;
	}

	private handleSharingError(err: Error) {
		console.error(err);
		new Notice(err.message, 7500);
	}
}
