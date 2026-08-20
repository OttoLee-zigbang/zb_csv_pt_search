import crypto from 'crypto';

// 실제 공개 서비스 도메인이 정해지면 ALLOWED_ORIGIN 환경변수로 지정해서 잠글 것.
// 지정하지 않으면(개발/초기 배포) 기존 동작 유지를 위해 '*'로 열어둠 — 되도록 빨리 도메인 지정 권장.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const ALLOWED_CATEGORIES = new Set(['도어락', '홈네트워크']);
const POSTCODE_RE = /^\d{5}$/;

// 구글 시트를 "웹에 게시(누구나 링크로 전체 다운로드 가능)" 대신, 서비스 계정으로만
// 읽을 수 있는 비공개 방식으로 접근한다. 아래 3개 환경변수는 Vercel 프로젝트
// Settings > Environment Variables 에서 직접 등록한다 (값은 절대 코드/채팅에 남기지 말 것).
//   GOOGLE_SERVICE_ACCOUNT_EMAIL   서비스 계정 JSON의 client_email
//   GOOGLE_SERVICE_ACCOUNT_KEY     서비스 계정 JSON의 private_key
//   GOOGLE_SHEET_ID                구글 시트 편집 화면 주소의 /d/와 /edit 사이 값
//   GOOGLE_SHEET_RANGE             (선택) 기본값 'A:D'
function base64url(input) {
    return Buffer.from(input)
        .toString('base64')
        .replace(/=+$/, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

let cachedToken = null; // { token, expiresAt } — 워밍업된 함수 인스턴스 사이에서 재사용

// Vercel 환경변수 입력창에 여러 줄 PEM 키를 붙여넣는 과정에서 줄바꿈이 깨지거나,
// JSON 파일의 "private_key": "..." 줄을 통째로(따옴표·쉼표 포함) 붙여넣는 경우가
// 흔해서, 앞뒤에 어떤 잡음이 있든 BEGIN~END 블록만 정확히 뽑아 항상 동일한
// 형태의 PEM으로 재구성한다.
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\uFEFF]/g; // 보이지 않는 폭 없는 문자
const SMART_DASH_RE = /[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g; // en/em dash, minus 등

function normalizePrivateKey(raw) {
    let key = (raw || '')
        .replace(ZERO_WIDTH_RE, '')
        .trim()
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '')
        .replace(SMART_DASH_RE, '-'); // 스마트/유니코드 대시를 일반 하이픈(-)으로 통일

    const match = key.match(/-----BEGIN (RSA )?PRIVATE KEY-----([\s\S]*?)-----END \1PRIVATE KEY-----/);
    if (!match) {
        console.error('키 형식 인식 실패 - 앞 20자 문자코드:', Array.from(key.slice(0, 20)).map((c) => c.charCodeAt(0)));
        return key;
    }

    const headerType = `${match[1] || ''}PRIVATE KEY`;
    const body = match[2].replace(/\s+/g, '');
    const lines = body.match(/.{1,64}/g) || [];
    return `-----BEGIN ${headerType}-----\n${lines.join('\n')}\n-----END ${headerType}-----\n`;
}

async function getAccessToken() {
    if (cachedToken && cachedToken.expiresAt > Date.now() + 30000) {
        return cachedToken.token;
    }

    const clientEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
    const privateKey = normalizePrivateKey(process.env.GOOGLE_SERVICE_ACCOUNT_KEY);

    if (!clientEmail || !privateKey) {
        throw new Error('구글 서비스 계정 환경변수가 설정되지 않았습니다.');
    }

    // 키 내용 자체는 절대 로그에 남기지 않고, 형태만 진단한다.
    console.error('키 진단(내용 아님):', {
        길이: privateKey.length,
        줄수: privateKey.split('\n').length,
        BEGIN로시작: privateKey.startsWith('-----BEGIN'),
        END로끝남: privateKey.trim().endsWith('-----'),
    });

    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const claim = {
        iss: clientEmail,
        scope: 'https://www.googleapis.com/auth/spreadsheets.readonly',
        aud: 'https://oauth2.googleapis.com/token',
        iat: now,
        exp: now + 3600,
    };

    const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;
    const signature = crypto.createSign('RSA-SHA256').update(unsigned).sign(privateKey);
    const jwt = `${unsigned}.${base64url(signature)}`;

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: jwt,
        }),
    });

    if (!tokenRes.ok) {
        const detail = await tokenRes.text().catch(() => '');
        console.error('구글 토큰 발급 응답 오류:', tokenRes.status, detail);
        throw new Error('구글 인증 토큰 발급 실패');
    }
    const tokenJson = await tokenRes.json();
    cachedToken = { token: tokenJson.access_token, expiresAt: Date.now() + tokenJson.expires_in * 1000 };
    return cachedToken.token;
}

async function fetchSheetRows() {
    const spreadsheetId = process.env.GOOGLE_SHEET_ID;
    const range = process.env.GOOGLE_SHEET_RANGE || 'A:D';

    if (!spreadsheetId) {
        throw new Error('GOOGLE_SHEET_ID 환경변수가 설정되지 않았습니다.');
    }

    const accessToken = await getAccessToken();
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(range)}`;
    const response = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
        const detail = await response.text().catch(() => '');
        console.error('구글 시트 API 응답 오류:', response.status, detail);
        throw new Error('구글 시트 데이터 로드 실패');
    }
    const data = await response.json();
    return data.values || [];
}

export default async function handler(req, res) {
    // CORS 및 GET 요청 허용 설정
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    res.setHeader('Vary', 'Origin');

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { category, postcode } = req.query;

    if (!category || !postcode) {
        return res.status(400).json({ error: '필수 파라미터가 누락되었습니다.' });
    }

    if (!ALLOWED_CATEGORIES.has(category)) {
        return res.status(400).json({ error: '유효하지 않은 제품군입니다.' });
    }

    if (Array.isArray(postcode) || !POSTCODE_RE.test(postcode.padStart(5, '0'))) {
        return res.status(400).json({ error: '유효하지 않은 우편번호입니다.' });
    }

    try {
        const rows = await fetchSheetRows();
        const matchedBranches = [];
        const cleanInputPostcode = postcode.padStart(5, '0');

        // 첫 행은 헤더이므로 건너뛴다.
        for (let i = 1; i < rows.length; i++) {
            const row = rows[i];
            if (!row || row.length < 3) continue;

            const bCategory = (row[0] ?? '').toString().trim();
            const bName = (row[1] ?? '').toString().trim();
            const bPostcode = (row[2] ?? '').toString().trim();
            const bPhone = (row[3] ?? '').toString().trim() || '연락처 없음';

            if (!bPostcode) continue;

            const cleanBranchPostcode = bPostcode.padStart(5, '0');
            if (bCategory === category && cleanBranchPostcode === cleanInputPostcode) {
                matchedBranches.push({ name: bName, category: bCategory, phone: bPhone });
            }
        }

        // 동일 조회를 CDN에서 잠깐 캐싱해 구글 API 호출량과 스크래핑 부담을 줄인다.
        res.setHeader('Cache-Control', 'public, max-age=60, s-maxage=60, stale-while-revalidate=120');
        return res.status(200).json({ branches: matchedBranches });

    } catch (error) {
        console.error('서버 내부 오류:', error);
        return res.status(500).json({ error: '데이터를 조회하는 중 서버 오류가 발생했습니다.' });
    }
}
