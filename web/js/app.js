(() => {
    'use strict';

    const PAGE_SIZE = 20;
    const STORAGE_ACCOUNT = 'byhz_account';
    const STORAGE_KIND = 'byhz_kind';
    const AGORA_SDK_URL = 'https://cdn.jsdelivr.net/npm/agora-rtc-sdk-ng@4.20.0/AgoraRTC_N-production.js';

    const state = {
        // list state
        tab: 'hot',            // hot | plat | search
        view: 'hot',           // hot | plats | platform | search
        platId: '',
        platName: '',
        key: '',
        page: 1,
        rooms: [],
        total: 0,
        plats: [],
        platsLoading: false,
        loadingRooms: false,
        roomsController: null,
        roomsRequest: 0,
        selectedKey: '',
        currentRoom: null,

        // playback state
        hls: null,
        mpegts: null,
        agora: null,
        agoraStream: null,
        agoraVideoTracks: new Map(),
        agoraAudioTracks: new Map(),
        agoraFallbackAudio: new Set(),
        playbackToken: 0,
        agoraLoader: null,

        // ui state
        toastTimer: null,
    };

    const el = {};

    document.addEventListener('DOMContentLoaded', init);

    function init() {
        cacheElements();
        bindEvents();
        restoreLogin();
        updateSidebarButtons(!isMobileViewport());
        bootstrap();
        window.setInterval(() => refreshStatus(true), 45000);
    }

    function cacheElements() {
        el.sidebar = document.getElementById('sidebar');
        el.overlay = document.getElementById('overlay');
        el.menuToggle = document.getElementById('menuToggle');
        el.sidebarClose = document.getElementById('sidebarClose');
        el.roomList = document.getElementById('roomList');
        el.platList = document.getElementById('platList');
        el.searchInput = document.getElementById('searchInput');
        el.tabHot = document.getElementById('tabHot');
        el.tabPlat = document.getElementById('tabPlat');
        el.listLabel = document.getElementById('listLabel');
        el.visibleCount = document.getElementById('visibleCount');
        el.roomCount = document.getElementById('roomCount');
        el.connectionDot = document.getElementById('connectionDot');
        el.connectionStatus = document.getElementById('connectionStatus');
        el.memberPill = document.getElementById('memberPill');
        el.accountToggle = document.getElementById('accountToggle');
        el.settingsToggle = document.getElementById('settingsToggle');
        el.logoutBtn = document.getElementById('logoutBtn');
        el.loginPanel = document.getElementById('loginPanel');
        el.settingsPanel = document.getElementById('settingsPanel');
        el.loginKind = document.getElementById('loginKind');
        el.loginAccount = document.getElementById('loginAccount');
        el.loginPassword = document.getElementById('loginPassword');
        el.memberLogin = document.getElementById('memberLogin');
        el.baseInput = document.getElementById('baseInput');
        el.saveBase = document.getElementById('saveBase');
        el.relogin = document.getElementById('relogin');
        el.moreBtn = document.getElementById('moreBtn');
        el.roomTitle = document.getElementById('roomTitle');
        el.modeBadge = document.getElementById('modeBadge');
        el.loadingRing = document.getElementById('loadingRing');
        el.liveDot = document.getElementById('liveDot');
        el.player = document.getElementById('player');
        el.playerEmpty = document.getElementById('playerEmpty');
        el.playerNotice = document.getElementById('playerNotice');
        el.openChannelsBtn = document.getElementById('openChannelsBtn');
        el.infoText = document.getElementById('infoText');
        el.infoOrigin = document.getElementById('infoOrigin');
        el.toast = document.getElementById('toast');
    }

    function bindEvents() {
        el.tabHot.addEventListener('click', () => switchTab('hot'));
        el.tabPlat.addEventListener('click', () => switchTab('plat'));
        el.moreBtn.addEventListener('click', () => loadRooms(false));
        el.searchInput.addEventListener('keydown', onSearchKeydown);
        el.roomList.addEventListener('click', onRoomClick);
        el.platList.addEventListener('click', onPlatformClick);

        el.accountToggle.addEventListener('click', () => togglePanel(el.loginPanel));
        el.settingsToggle.addEventListener('click', () => togglePanel(el.settingsPanel));
        el.memberLogin.addEventListener('click', memberLogin);
        el.logoutBtn.addEventListener('click', memberLogout);
        el.saveBase.addEventListener('click', saveBase);
        el.relogin.addEventListener('click', relogin);

        el.loginAccount.addEventListener('keydown', event => {
            if (event.key === 'Enter') el.loginPassword.focus();
        });
        el.loginPassword.addEventListener('keydown', event => {
            if (event.key === 'Enter') memberLogin();
        });

        el.menuToggle.addEventListener('click', () => toggleSidebar());
        el.sidebarClose.addEventListener('click', () => toggleSidebar(false));
        el.overlay.addEventListener('click', () => toggleSidebar(false));
        el.openChannelsBtn.addEventListener('click', () => toggleSidebar(true));
        el.player.addEventListener('volumechange', applyAgoraVolumeState);

        document.addEventListener('keydown', onDocumentKeydown);
        window.addEventListener('resize', onWindowResize);
    }

    /* -------------------------------------------------------------- */
    /* bootstrap / status / session                                    */
    /* -------------------------------------------------------------- */

    async function bootstrap() {
        setListState('正在加载房间...', 'loading');
        const status = await refreshStatus(true);
        if (status && !status.logged_in && status.base) {
            try {
                await api('/api/relogin', { method: 'POST' });
            } catch (error) {
                showToast('自动登录失败：' + error.message, 'error');
            }
            await refreshStatus(true);
        }
        await refreshSession();
        await loadRooms(true);
    }

    async function api(path, options = {}) {
        const { body, headers, ...rest } = options;
        const request = {
            ...rest,
            headers: {
                Accept: 'application/json',
                ...(body !== undefined ? { 'Content-Type': 'application/json' } : null),
                ...(headers || {}),
            },
        };
        if (body !== undefined) request.body = JSON.stringify(body);

        const response = await fetch(path, request);
        const text = await response.text();
        let data = null;
        if (text) {
            try {
                data = JSON.parse(text);
            } catch (_error) {
                data = { detail: text };
            }
        }
        if (!response.ok) throw new Error(extractError(data, response));
        return data;
    }

    function extractError(data, response) {
        if (data && typeof data === 'object') {
            const detail = data.detail || data.msg || data.message;
            if (typeof detail === 'string' && detail.trim()) return detail.trim();
        }
        return 'HTTP ' + response.status;
    }

    async function refreshStatus(silent) {
        try {
            const info = await api('/api/status');
            setConnection(true);
            if (info && info.base && !el.baseInput.value.trim()) {
                el.baseInput.value = info.base;
            }
            applySession(info);
            return info;
        } catch (error) {
            setConnection(false);
            if (!silent) showToast('本地服务连接失败：' + error.message, 'error');
            return null;
        }
    }

    async function refreshSession() {
        try {
            const session = await api('/api/session');
            applySession(session);
            return session;
        } catch (_error) {
            return null;
        }
    }

    function applySession(info) {
        if (!info) return;
        const member = !!info.member;
        const account = typeof info.account === 'string' ? info.account.trim() : '';
        el.memberPill.textContent = member && account ? '会员 · ' + account : (member ? '会员' : '游客');
        el.memberPill.title = el.memberPill.textContent;
        el.memberPill.classList.toggle('member', member);
        el.logoutBtn.classList.toggle('hidden', !member);
        el.accountToggle.textContent = member ? '切换账号' : '会员登录';
        if (member) el.loginPanel.classList.add('hidden');
    }

    function setConnection(online) {
        el.connectionStatus.textContent = online ? '在线' : '离线';
        el.connectionDot.classList.toggle('offline', !online);
    }

    /* -------------------------------------------------------------- */
    /* room list                                                       */
    /* -------------------------------------------------------------- */

    function switchTab(tab) {
        if (tab === 'hot') {
            state.tab = 'hot';
            state.view = 'hot';
            state.platId = '';
            state.platName = '';
            state.key = '';
            el.searchInput.value = '';
            showRoomsPanel(true);
            updateTabs();
            updateSummary();
            loadRooms(true);
            return;
        }
        state.tab = 'plat';
        state.view = 'plats';
        state.platId = '';
        state.platName = '';
        state.key = '';
        el.searchInput.value = '';
        updateTabs();
        updateSummary();
        showRoomsPanel(false);
        loadPlats();
    }

    function submitSearch() {
        const key = el.searchInput.value.trim();
        if (!key) {
            if (state.view === 'search') switchTab('hot');
            return;
        }
        state.tab = 'search';
        state.view = 'search';
        state.key = key;
        state.platId = '';
        state.platName = '';
        updateTabs();
        updateSummary();
        showRoomsPanel(true);
        loadRooms(true);
    }

    function onSearchKeydown(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            submitSearch();
            return;
        }
        if (event.key === 'Escape') {
            el.searchInput.value = '';
            if (state.view === 'search') switchTab('hot');
            el.searchInput.blur();
        }
    }

    async function loadRooms(reset) {
        if (!reset && state.loadingRooms) return;

        if (state.roomsController) {
            try { state.roomsController.abort(); } catch (_error) {}
        }
        const controller = new AbortController();
        state.roomsController = controller;
        const requestId = ++state.roomsRequest;
        const page = reset ? 1 : state.page + 1;

        state.loadingRooms = true;
        if (reset) {
            setListState('正在加载房间...', 'loading');
        }
        updateMoreButton();

        try {
            const params = new URLSearchParams({
                page: String(page),
                page_size: String(PAGE_SIZE),
            });
            let path;
            if (state.tab === 'search') {
                path = '/api/search?key=' + encodeURIComponent(state.key) + '&' + params.toString();
            } else {
                if (state.tab === 'plat' && state.platId) params.set('plat_id', state.platId);
                path = '/api/rooms?' + params.toString();
            }

            const data = await api(path, { signal: controller.signal });
            if (requestId !== state.roomsRequest) return;

            const rawList = Array.isArray(data && data.list) ? data.list : [];
            const rooms = rawList.map(normalizeRoom).filter(room => room.roomId);
            const count = Number(data && data.count);
            state.total = Number.isFinite(count) && count >= 0
                ? count
                : (reset ? rooms.length : state.rooms.length + rooms.length);
            state.rooms = reset ? rooms : state.rooms.concat(rooms);
            state.page = page;

            setConnection(true);
            if (!state.rooms.length) {
                setListState(state.tab === 'search' ? '没有匹配的直播间' : '暂无直播间', 'empty');
            } else {
                renderRooms();
            }
            updateSummary();
        } catch (error) {
            if (error.name === 'AbortError' || requestId !== state.roomsRequest) return;
            setConnection(false);
            showToast('房间列表加载失败：' + error.message, 'error');
            if (!state.rooms.length) {
                setListState('加载失败：' + error.message, 'error');
            }
        } finally {
            if (requestId === state.roomsRequest) {
                state.loadingRooms = false;
                state.roomsController = null;
                updateMoreButton();
            }
        }
    }

    function normalizeRoom(item) {
        const roomId = item.room_id != null
            ? String(item.room_id)
            : (item.id != null ? String(item.id) : '');
        return {
            roomId,
            platId: item.plat_id != null ? String(item.plat_id) : '',
            name: firstNonEmpty(item.name, item.title, item.plat_name, roomId ? '房间 ' + roomId : '未命名'),
            platName: firstNonEmpty(item.plat_name, item.platform, ''),
            cover: firstNonEmpty(item.cover, item.plat_cover, ''),
            online: item.online != null ? String(item.online) : '',
            locked: !!item.is_locked,
        };
    }

    function normalizePlatform(item) {
        return {
            id: item.id != null
                ? String(item.id)
                : (item.plat_id != null ? String(item.plat_id) : ''),
            name: firstNonEmpty(item.name, item.plat_name, item.channel_name, '未命名平台'),
            cover: firstNonEmpty(item.cover, item.plat_cover, ''),
            roomCount: Number(item.room_count) || 0,
        };
    }

    function renderRooms() {
        if (!state.rooms.length) {
            setListState(state.tab === 'search' ? '没有匹配的直播间' : '暂无直播间', 'empty');
            return;
        }
        const fragment = document.createDocumentFragment();
        state.rooms.forEach((room, index) => {
            fragment.appendChild(createRoomRow(room, index));
        });
        el.roomList.replaceChildren(fragment);
        updateMoreButton();
    }

    function createRoomRow(room, index) {
        const selected = roomKey(room) === state.selectedKey;

        const row = document.createElement('li');
        row.className = 'room-row';
        row.setAttribute('role', 'option');
        row.setAttribute('aria-selected', String(selected));

        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'room-button';
        button.dataset.index = String(index);
        button.setAttribute('aria-selected', String(selected));
        button.setAttribute('aria-label', '播放 ' + room.name);
        button.title = room.name;

        const cover = document.createElement('span');
        cover.className = 'room-cover';
        const fallback = document.createElement('span');
        fallback.className = 'cover-fallback';
        fallback.textContent = 'LIVE';
        cover.appendChild(fallback);

        if (isSafeImageURL(room.cover)) {
            const image = document.createElement('img');
            image.alt = room.name;
            image.loading = 'lazy';
            image.decoding = 'async';
            image.src = room.cover;
            image.addEventListener('error', () => image.remove(), { once: true });
            cover.appendChild(image);
        }

        const details = document.createElement('span');
        details.className = 'room-details';
        const name = document.createElement('span');
        name.className = 'room-name';
        name.textContent = room.name;
        const meta = document.createElement('span');
        meta.className = 'room-meta';

        const platform = document.createElement('span');
        platform.className = 'room-platform';
        platform.textContent = room.platName || '直播';
        meta.appendChild(platform);

        if (room.locked) {
            const lock = document.createElement('span');
            lock.className = 'room-lock';
            lock.textContent = '密码房';
            meta.appendChild(lock);
        } else if (room.online !== '') {
            const online = document.createElement('span');
            online.className = 'room-online';
            online.textContent = room.online + ' 在线';
            meta.appendChild(online);
        }

        details.append(name, meta);
        button.append(cover, details);
        row.appendChild(button);
        return row;
    }

    function setListState(message, kind) {
        const row = document.createElement('li');
        row.className = 'state-row' + (kind ? ' ' + kind : '');
        row.textContent = message;
        el.roomList.replaceChildren(row);
    }

    function onRoomClick(event) {
        const button = event.target.closest('button[data-index]');
        if (!button) return;
        const index = Number(button.dataset.index);
        if (!Number.isInteger(index)) return;
        const room = state.rooms[index];
        if (!room) return;
        closeMobileDrawer();
        openRoom(room);
    }

    function roomKey(room) {
        return room.roomId + '|' + room.platId;
    }

    function updateSelection() {
        el.roomList.querySelectorAll('button[data-index]').forEach(button => {
            const room = state.rooms[Number(button.dataset.index)];
            const selected = !!room && roomKey(room) === state.selectedKey;
            button.setAttribute('aria-selected', String(selected));
            const row = button.parentElement;
            if (row) row.setAttribute('aria-selected', String(selected));
        });
    }

    /* -------------------------------------------------------------- */
    /* platforms                                                       */
    /* -------------------------------------------------------------- */

    async function loadPlats() {
        if (state.platsLoading) return;
        state.platsLoading = true;
        el.platList.replaceChildren(createPlatformState('正在加载平台...', 'loading'));

        try {
            const data = await api('/api/plats');
            const list = Array.isArray(data && data.list) ? data.list : [];
            state.plats = list.map(normalizePlatform).filter(platform => platform.id);
            renderPlatforms();
            updateSummary();
        } catch (error) {
            el.platList.replaceChildren(createPlatformState('平台加载失败：' + error.message, 'error'));
            showToast('平台列表加载失败：' + error.message, 'error');
        } finally {
            state.platsLoading = false;
        }
    }

    function renderPlatforms() {
        if (!state.plats.length) {
            el.platList.replaceChildren(createPlatformState('暂无平台', 'empty'));
            return;
        }
        const fragment = document.createDocumentFragment();
        state.plats.forEach(platform => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'platform-button';
            button.dataset.platId = platform.id;
            button.setAttribute('role', 'option');
            button.setAttribute('aria-label', '查看 ' + platform.name + ' 的直播间');
            button.title = platform.name;

            const fallback = () => {
                const span = document.createElement('span');
                span.className = 'platform-logo-fallback';
                span.textContent = platform.name.slice(0, 2);
                return span;
            };

            if (isSafeImageURL(platform.cover)) {
                const image = document.createElement('img');
                image.className = 'platform-logo';
                image.alt = platform.name;
                image.loading = 'lazy';
                image.src = platform.cover;
                image.addEventListener('error', () => image.replaceWith(fallback()), { once: true });
                button.appendChild(image);
            } else {
                button.appendChild(fallback());
            }

            const name = document.createElement('span');
            name.className = 'platform-name';
            name.textContent = platform.name;
            const count = document.createElement('span');
            count.className = 'platform-count';
            count.textContent = platform.roomCount > 0 ? platform.roomCount + ' 个房间' : '查看房间';

            button.append(name, count);
            fragment.appendChild(button);
        });
        el.platList.replaceChildren(fragment);
    }

    function createPlatformState(message, kind) {
        const div = document.createElement('div');
        div.className = 'state-row' + (kind ? ' ' + kind : '');
        div.textContent = message;
        return div;
    }

    function onPlatformClick(event) {
        const button = event.target.closest('button[data-plat-id]');
        if (!button) return;
        const platform = state.plats.find(item => item.id === button.dataset.platId);
        if (!platform) return;
        state.tab = 'plat';
        state.view = 'platform';
        state.platId = platform.id;
        state.platName = platform.name;
        state.key = '';
        el.searchInput.value = '';
        updateTabs();
        updateSummary();
        showRoomsPanel(true);
        loadRooms(true);
    }

    /* -------------------------------------------------------------- */
    /* list chrome                                                     */
    /* -------------------------------------------------------------- */

    function showRoomsPanel(showRooms) {
        el.roomList.classList.toggle('hidden', !showRooms);
        el.platList.classList.toggle('hidden', showRooms);
        if (showRooms) updateMoreButton();
        else el.moreBtn.classList.add('hidden');
    }

    function updateTabs() {
        const hotActive = state.tab === 'hot';
        const platActive = state.tab === 'plat';
        el.tabHot.classList.toggle('active', hotActive);
        el.tabHot.setAttribute('aria-selected', String(hotActive));
        el.tabPlat.classList.toggle('active', platActive);
        el.tabPlat.setAttribute('aria-selected', String(platActive));
    }

    function updateSummary() {
        let label = '房间列表';
        if (state.view === 'plats') label = '平台列表';
        else if (state.view === 'platform') label = state.platName || '平台房间';
        else if (state.view === 'search') label = '搜索结果';

        el.listLabel.textContent = label;
        el.visibleCount.textContent = String(state.view === 'plats' ? state.plats.length : state.rooms.length);
        if (state.view !== 'plats') {
            el.roomCount.textContent = state.total > 0
                ? state.total + ' 个房间'
                : state.rooms.length + ' 个房间';
        }
    }

    function updateMoreButton() {
        const visible = state.view !== 'plats' && state.rooms.length > 0 && state.rooms.length < state.total;
        el.moreBtn.classList.toggle('hidden', !visible);
        el.moreBtn.disabled = state.loadingRooms;
        el.moreBtn.textContent = state.loadingRooms ? '加载中…' : '加载更多';
    }

    /* -------------------------------------------------------------- */
    /* room playback                                                   */
    /* -------------------------------------------------------------- */

    async function openRoom(room) {
        if (!room) return;

        let pwd = '';
        if (room.locked) {
            const entered = window.prompt('该直播间需要密码：', '');
            if (entered === null) return;
            pwd = entered.trim();
            if (!pwd) {
                showToast('密码不能为空', 'error');
                return;
            }
        }

        state.selectedKey = roomKey(room);
        state.currentRoom = room;
        updateSelection();

        // Stop the previous stream immediately; otherwise it keeps playing
        // behind the loading state and any failure notice.
        teardownPlayer();
        el.playerEmpty.hidden = true;
        el.roomTitle.textContent = room.name;
        setModeBadge('', '');
        setOrigin('');
        setInfo('正在获取播放参数…');
        setBusy(true);

        try {
            const params = new URLSearchParams({ room_id: room.roomId });
            if (room.platId) params.set('plat_id', room.platId);
            if (pwd) params.set('pwd', pwd);

            const info = await api('/api/room?' + params.toString());
            playInfo(info, room);
        } catch (error) {
            showPlaybackError('获取播放参数失败：' + error.message);
        } finally {
            setBusy(false);
        }
    }

    function playInfo(info, room) {
        if (!info || typeof info !== 'object') {
            showPlaybackError('播放参数为空');
            return;
        }

        state.currentRoom = room || state.currentRoom;
        const token = teardownPlayer();
        el.playerEmpty.hidden = true;

        el.roomTitle.textContent = firstNonEmpty(info.name, room && room.name, '直播间');
        setModeBadge(info.mode, info.format);
        setOrigin(info.origin || '');
        setInfo(info.note || defaultPlaybackNote(info));

        switch (info.mode) {
            case 'agora':
                joinAgora(info, token);
                break;
            case 'unsupported':
                showUnsupported(info, room, token);
                break;
            case 'hls':
                if (info.format === 'flv') playFlv(info, token);
                else playHls(info, token);
                break;
            default:
                showPlaybackError('未知播放模式：' + info.mode);
        }
    }

    function defaultPlaybackNote(info) {
        if (info.mode === 'agora') return 'Agora 频道，正在加入…';
        if (info.format === 'flv') return 'FLV 直播流，经本地 relay 转发。';
        if (info.mode === 'hls') return 'HLS 直播流，经本地 relay 转发。';
        return '已获取播放参数。';
    }

    function teardownPlayer() {
        state.playbackToken += 1;

        if (state.hls) {
            try { state.hls.destroy(); } catch (_error) {}
            state.hls = null;
        }
        if (state.mpegts) {
            try { state.mpegts.destroy(); } catch (_error) {}
            state.mpegts = null;
        }
        if (state.agora) {
            const client = state.agora;
            state.agora = null;
            try {
                const leaving = client.leave();
                if (leaving && typeof leaving.catch === 'function') leaving.catch(() => {});
            } catch (_error) {}
        }

        try { el.player.pause(); } catch (_error) {}
        try {
            el.player.srcObject = null;
            el.player.removeAttribute('src');
            el.player.load();
        } catch (_error) {}
        el.player.hidden = false;
        state.agoraStream = null;
        state.agoraVideoTracks.clear();
        state.agoraAudioTracks.clear();
        state.agoraFallbackAudio.clear();
        el.playerNotice.classList.add('hidden');
        el.playerNotice.replaceChildren();
        setLive(false);

        return state.playbackToken;
    }

    function playHls(info, token) {
        if (!info.url) {
            showPlaybackError('缺少播放地址');
            return;
        }
        const video = el.player;

        if (window.Hls && window.Hls.isSupported()) {
            const hls = new window.Hls({
                lowLatencyMode: true,
                liveSyncDurationCount: 3,
                manifestLoadingTimeOut: 15000,
                fragLoadingTimeOut: 30000,
                backBufferLength: 60,
            });
            state.hls = hls;

            hls.on(window.Hls.Events.MANIFEST_PARSED, () => {
                if (token !== state.playbackToken) return;
                setLive(true);
                setInfo('播放器已连接 · HLS');
                video.play().catch(() => {
                    if (token === state.playbackToken) setInfo('浏览器拦截了自动播放，请点击播放');
                });
            });
            hls.on(window.Hls.Events.ERROR, (_event, data) => {
                if (token !== state.playbackToken || !data || !data.fatal) return;
                if (data.type === window.Hls.ErrorTypes.NETWORK_ERROR) {
                    setInfo('网络错误，正在尝试恢复…');
                    try { hls.startLoad(); } catch (_error) {}
                } else if (data.type === window.Hls.ErrorTypes.MEDIA_ERROR) {
                    setInfo('媒体错误，正在尝试恢复…');
                    try { hls.recoverMediaError(); } catch (_error) {}
                } else {
                    showPlaybackError('HLS 播放失败：' + (data.details || data.type || '未知错误'));
                }
            });

            hls.loadSource(info.url);
            hls.attachMedia(video);
            return;
        }

        if (video.canPlayType('application/vnd.apple.mpegurl')) {
            video.addEventListener('loadedmetadata', () => {
                if (token !== state.playbackToken) return;
                setLive(true);
                setInfo('播放器已连接 · 原生 HLS');
                video.play().catch(() => {});
            }, { once: true });
            video.src = info.url;
            video.load();
            return;
        }

        showPlaybackError('当前浏览器不支持 HLS 播放');
    }

    function playFlv(info, token) {
        if (!info.url) {
            showPlaybackError('缺少播放地址');
            return;
        }
        const video = el.player;

        if (!window.mpegts || !window.mpegts.isSupported()) {
            video.src = info.url;
            video.play().catch(() => {});
            setInfo('当前浏览器不支持 mpegts.js，尝试直接播放');
            return;
        }

        const player = window.mpegts.createPlayer(
            { type: 'flv', isLive: true, url: info.url },
            {
                enableStashBuffer: false,
                stashInitialSize: 128,
                lazyLoad: false,
                liveBufferLatencyChasing: true,
                liveBufferLatencyMaxLatency: 4,
                liveBufferLatencyMinRemain: 1,
                fixAudioTimestampGap: true,
            }
        );
        state.mpegts = player;
        player.attachMediaElement(video);
        player.load();
        player.play().catch(() => {
            if (token === state.playbackToken) setInfo('浏览器拦截了自动播放，请点击播放');
        });
        player.on(window.mpegts.Events.ERROR, (type, detail) => {
            if (token !== state.playbackToken) return;
            showPlaybackError('FLV 播放错误：' + (detail || type || '上游流不可用'));
        });
        player.on(window.mpegts.Events.MEDIA_INFO, () => {
            if (token !== state.playbackToken) return;
            setLive(true);
            setInfo('播放器已连接 · FLV');
        });
    }

    function loadAgoraSDK() {
        if (window.AgoraRTC) return Promise.resolve(window.AgoraRTC);
        if (state.agoraLoader) return state.agoraLoader;

        state.agoraLoader = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = AGORA_SDK_URL;
            script.async = true;
            script.onload = () => {
                if (window.AgoraRTC) resolve(window.AgoraRTC);
                else reject(new Error('Agora SDK 初始化失败'));
            };
            script.onerror = () => reject(new Error('无法从 CDN 加载 Agora SDK，请检查网络'));
            document.head.appendChild(script);
        }).catch(error => {
            state.agoraLoader = null;
            throw error;
        });
        return state.agoraLoader;
    }

    async function joinAgora(info, token) {
        if (!info.appId || !info.channelId) {
            showPlaybackError('Agora 参数不完整（缺少 appId 或 channelId）');
            return;
        }

        setInfo('正在加载 Agora Web SDK…');
        let AgoraRTC;
        try {
            AgoraRTC = await loadAgoraSDK();
        } catch (error) {
            if (token === state.playbackToken) showPlaybackError(error.message);
            return;
        }
        if (token !== state.playbackToken) return;

        // Feed the remote tracks into the same native <video> element used by
        // HLS/FLV, so volume, mute and fullscreen keep the browser controls.
        const stream = new MediaStream();
        state.agoraStream = stream;
        el.player.srcObject = stream;
        setInfo('正在加入 Agora 频道…');

        const client = AgoraRTC.createClient({ mode: 'live', codec: 'vp8' });
        state.agora = client;

        client.on('user-published', async (user, mediaType) => {
            try {
                await client.subscribe(user, mediaType);
            } catch (error) {
                if (token === state.playbackToken) showToast('订阅远端流失败：' + error, 'error');
                return;
            }
            if (token !== state.playbackToken) return;

            if (mediaType === 'video' && user.videoTrack) {
                const mediaTrack = mediaStreamTrackOf(user.videoTrack);
                if (!mediaTrack) {
                    showPlaybackError('无法读取 Agora 远端视频轨道');
                    return;
                }
                state.agoraVideoTracks.set(user.videoTrack, mediaTrack);
                stream.addTrack(mediaTrack);
                startAgoraPlayback(token);
            }

            if (mediaType === 'audio' && user.audioTrack) {
                const mediaTrack = mediaStreamTrackOf(user.audioTrack);
                if (mediaTrack) {
                    state.agoraAudioTracks.set(user.audioTrack, mediaTrack);
                    stream.addTrack(mediaTrack);
                    startAgoraPlayback(token);
                } else {
                    // Fall back to SDK audio playback; keep the native volume
                    // slider working by forwarding it to setVolume().
                    state.agoraFallbackAudio.add(user.audioTrack);
                    try { user.audioTrack.play(); } catch (_error) {}
                    applyAgoraVolumeState();
                }
            }
        });

        client.on('user-unpublished', (user, mediaType) => {
            if (mediaType === 'video' && user.videoTrack) {
                const mediaTrack = state.agoraVideoTracks.get(user.videoTrack);
                if (mediaTrack) stream.removeTrack(mediaTrack);
                state.agoraVideoTracks.delete(user.videoTrack);
                try { user.videoTrack.stop(); } catch (_error) {}
            }
            if (mediaType === 'audio' && user.audioTrack) {
                const mediaTrack = state.agoraAudioTracks.get(user.audioTrack);
                if (mediaTrack) stream.removeTrack(mediaTrack);
                state.agoraAudioTracks.delete(user.audioTrack);
                state.agoraFallbackAudio.delete(user.audioTrack);
                try { user.audioTrack.stop(); } catch (_error) {}
            }
        });

        try {
            await client.setClientRole('audience');
            let uid = info.uid;
            if (uid === undefined || uid === null || uid === '') uid = null;
            else if (/^\d+$/.test(String(uid))) uid = Number(uid);

            await client.join(info.appId, String(info.channelId), info.token || null, uid);
            if (token !== state.playbackToken) {
                try { await client.leave(); } catch (_error) {}
                return;
            }
            setLive(true);
            setInfo('已加入 Agora 频道 ' + info.channelId + '（观众）');
        } catch (error) {
            if (token !== state.playbackToken) return;
            state.agora = null;
            try { await client.leave(); } catch (_error) {}
            el.player.srcObject = null;
            state.agoraStream = null;
            state.agoraVideoTracks.clear();
            state.agoraAudioTracks.clear();
            state.agoraFallbackAudio.clear();
            showPlaybackError('加入 Agora 频道失败：' + (error && error.message ? error.message : error));
        }
    }

    function mediaStreamTrackOf(track) {
        if (!track || typeof track.getMediaStreamTrack !== 'function') return null;
        try {
            const mediaTrack = track.getMediaStreamTrack();
            return mediaTrack && mediaTrack.readyState === 'live' ? mediaTrack : null;
        } catch (_error) {
            return null;
        }
    }

    function startAgoraPlayback(token) {
        if (token !== state.playbackToken) return;
        const result = el.player.play();
        if (result && typeof result.catch === 'function') {
            result.catch(() => {
                if (token === state.playbackToken) {
                    setInfo('浏览器拦截了自动播放，请点击播放按钮');
                }
            });
        }
    }

    function applyAgoraVolumeState() {
        if (!state.agoraFallbackAudio.size) return;
        const volume = el.player.muted ? 0 : Math.round(el.player.volume * 100);
        state.agoraFallbackAudio.forEach(track => {
            try {
                if (typeof track.setVolume === 'function') track.setVolume(volume);
            } catch (_error) {}
        });
    }

    function showUnsupported(info, room) {
        el.playerEmpty.hidden = true;
        setLive(false);

        const card = document.createElement('div');
        card.className = 'notice-card';

        const title = document.createElement('h2');
        title.textContent = info.reason === 'yunceng'
            ? '暂时无法生成 Agora Token'
            : '该直播间暂时无法直接播放';
        card.appendChild(title);

        const note = document.createElement('p');
        note.textContent = info.note ||
            '服务端未能生成可用的播放参数，请稍后重试或选择其他直播间。';
        card.appendChild(note);
        const actions = buildNoticeActions(room || state.currentRoom);
        if (actions) card.appendChild(actions);

        el.playerNotice.replaceChildren(card);
        el.playerNotice.classList.remove('hidden');
        setInfo(note.textContent);
    }

    function buildNoticeActions(room) {
        if (!room) return null;

        const actions = document.createElement('div');
        actions.className = 'notice-actions';

        const retry = document.createElement('button');
        retry.type = 'button';
        retry.className = 'secondary-button';
        retry.textContent = '重试';
        retry.addEventListener('click', () => openRoom(room));
        actions.appendChild(retry);

        return actions;
    }

    function showPlaybackError(message) {
        teardownPlayer();
        setBusy(false);
        setInfo(message, 'error');
        showToast(message, 'error');

        const card = document.createElement('div');
        card.className = 'notice-card';

        const title = document.createElement('h2');
        title.textContent = '播放失败';

        const note = document.createElement('p');
        note.textContent = message;

        card.append(title, note);
        const actions = buildNoticeActions(state.currentRoom);
        if (actions) card.appendChild(actions);

        el.playerNotice.replaceChildren(card);
        el.playerNotice.classList.remove('hidden');
        el.playerEmpty.hidden = true;
    }

    /* -------------------------------------------------------------- */
    /* playback chrome                                                 */
    /* -------------------------------------------------------------- */

    function setBusy(on) {
        el.loadingRing.classList.toggle('hidden', !on);
    }

    function setLive(on) {
        el.liveDot.classList.toggle('is-live', on);
    }

    function setInfo(text, kind) {
        el.infoText.textContent = text || '';
        el.infoText.classList.toggle('error', kind === 'error');
    }

    function setOrigin(url) {
        el.infoOrigin.textContent = url ? '源: ' + url : '';
        el.infoOrigin.title = url || '';
    }

    function setModeBadge(mode, format) {
        if (!mode) {
            el.modeBadge.classList.add('hidden');
            el.modeBadge.textContent = '';
            return;
        }
        let text = String(mode).toUpperCase();
        if (format && String(format).toLowerCase() !== String(mode).toLowerCase()) {
            text += ' · ' + String(format).toUpperCase();
        }
        el.modeBadge.textContent = text;
        el.modeBadge.classList.remove('hidden');
    }

    /* -------------------------------------------------------------- */
    /* settings / member                                               */
    /* -------------------------------------------------------------- */

    function togglePanel(panel) {
        const opening = panel.classList.contains('hidden');
        el.loginPanel.classList.add('hidden');
        el.settingsPanel.classList.add('hidden');
        if (opening) panel.classList.remove('hidden');
    }

    async function saveBase() {
        const base = el.baseInput.value.trim();
        el.saveBase.disabled = true;
        try {
            const result = await api('/api/base', { method: 'POST', body: { base } });
            setConnection(true);
            showToast('API 地址已保存', 'success');
            setInfo('API: ' + (result && result.base ? result.base : '自动发现'));
            await refreshStatus(true);
            await refreshSession();
            await loadRooms(true);
        } catch (error) {
            setConnection(false);
            showToast('保存失败：' + error.message, 'error');
        } finally {
            el.saveBase.disabled = false;
        }
    }

    async function relogin() {
        el.relogin.disabled = true;
        try {
            const result = await api('/api/relogin', { method: 'POST' });
            setConnection(true);
            showToast('游客登录成功', 'success');
            setInfo('游客登录成功 · API: ' + (result && result.base ? result.base : '自动'));
            await refreshSession();
            await loadRooms(true);
        } catch (error) {
            showToast('登录失败：' + error.message, 'error');
        } finally {
            el.relogin.disabled = false;
        }
    }

    async function memberLogin() {
        const kind = el.loginKind.value;
        const account = el.loginAccount.value.trim();
        const password = el.loginPassword.value;

        if (!account) {
            showToast('请输入会员账号', 'error');
            el.loginAccount.focus();
            return;
        }
        if (!password || password.length < 6) {
            showToast('密码至少 6 位', 'error');
            el.loginPassword.focus();
            return;
        }

        const originalLabel = el.memberLogin.textContent;
        el.memberLogin.disabled = true;
        el.memberLogin.textContent = '登录中…';

        try {
            const result = await api('/api/member_login', {
                method: 'POST',
                body: { kind, account, password },
            });
            storeValue(STORAGE_ACCOUNT, account);
            storeValue(STORAGE_KIND, kind);
            el.loginPassword.value = '';
            el.loginPanel.classList.add('hidden');
            await refreshSession();
            showToast('会员登录成功' + (result && result.name ? '：' + result.name : ''), 'success');
            loadRooms(true);
        } catch (error) {
            showToast('登录失败：' + error.message, 'error');
        } finally {
            el.memberLogin.disabled = false;
            el.memberLogin.textContent = originalLabel;
        }
    }

    async function memberLogout() {
        el.logoutBtn.disabled = true;
        try {
            await api('/api/logout', { method: 'POST' });
            await refreshSession();
            showToast('已退出会员，切回游客账号', 'success');
            loadRooms(true);
        } catch (error) {
            showToast('退出失败：' + error.message, 'error');
        } finally {
            el.logoutBtn.disabled = false;
        }
    }

    function restoreLogin() {
        el.loginAccount.value = readValue(STORAGE_ACCOUNT) || '';
        el.loginKind.value = readValue(STORAGE_KIND) || 'mobile';
    }

    function readValue(key) {
        try {
            return localStorage.getItem(key);
        } catch (_error) {
            return null;
        }
    }

    function storeValue(key, value) {
        try {
            localStorage.setItem(key, value);
        } catch (_error) {}
    }

    /* -------------------------------------------------------------- */
    /* sidebar / toast / helpers                                       */
    /* -------------------------------------------------------------- */

    function isMobileViewport() {
        return window.matchMedia('(max-width: 768px)').matches;
    }

    function toggleSidebar(forceOpen) {
        const mobile = isMobileViewport();
        const isOpen = mobile
            ? el.sidebar.classList.contains('open')
            : !el.sidebar.classList.contains('collapsed');
        const open = typeof forceOpen === 'boolean' ? forceOpen : !isOpen;

        if (mobile) {
            el.sidebar.classList.toggle('open', open);
            el.sidebar.classList.remove('collapsed');
            el.overlay.classList.toggle('active', open);
            el.overlay.setAttribute('aria-hidden', String(!open));
        } else {
            el.sidebar.classList.toggle('collapsed', !open);
            el.sidebar.classList.remove('open');
            el.overlay.classList.remove('active');
            el.overlay.setAttribute('aria-hidden', 'true');
        }

        updateSidebarButtons(open);
    }

    function updateSidebarButtons(open) {
        el.menuToggle.setAttribute('aria-expanded', String(open));
        el.menuToggle.setAttribute('aria-label', open ? '收起直播间列表' : '打开直播间列表');
        el.menuToggle.textContent = open ? '收起房间' : '房间列表';
    }

    function closeMobileDrawer() {
        if (isMobileViewport()) toggleSidebar(false);
    }

    function onWindowResize() {
        if (isMobileViewport()) {
            el.sidebar.classList.remove('collapsed');
            const open = el.sidebar.classList.contains('open');
            el.overlay.classList.toggle('active', open);
            updateSidebarButtons(open);
        } else {
            el.overlay.classList.remove('active');
            el.overlay.setAttribute('aria-hidden', 'true');
            updateSidebarButtons(!el.sidebar.classList.contains('collapsed'));
        }
    }

    function onDocumentKeydown(event) {
        if (event.key === 'Escape') {
            toggleSidebar(false);
            return;
        }
        if (event.key === '/' && !isTypingTarget(event.target)) {
            event.preventDefault();
            el.searchInput.focus();
        }
    }

    function isTypingTarget(target) {
        if (!target || !target.tagName) return false;
        const tag = target.tagName.toUpperCase();
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
    }

    function showToast(message, kind) {
        window.clearTimeout(state.toastTimer);
        el.toast.textContent = message;
        el.toast.className = 'toast visible' + (kind ? ' ' + kind : '');
        state.toastTimer = window.setTimeout(() => {
            el.toast.className = 'toast';
        }, 3600);
    }

    function firstNonEmpty(...values) {
        for (const value of values) {
            if (value === undefined || value === null) continue;
            const text = String(value).trim();
            if (text) return text;
        }
        return '';
    }

    function isSafeImageURL(raw) {
        if (!raw) return false;
        try {
            const parsed = new URL(raw, window.location.origin);
            return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch (_error) {
            return false;
        }
    }
})();
