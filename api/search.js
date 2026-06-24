import fetch from 'node-fetch';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { category, postcode } = req.query;

    if (!category || !postcode) {
        return res.status(400).json({ error: '필수 파라미터가 누락되었습니다.' });
    }

    const googleSheetCsvUrl = "https://docs.google.com/spreadsheets/d/e/2PACX-1vRNQCQJ6a31n8CaHsbys-hZTkrPPWr36q5txpGP9UjZsxG-0XbyRLf7qhAKx7fme3KAlG9LTejSpiI_/pub?gid=0&single=true&output=csv&nocache=" + new Date().getTime();

    try {
        const response = await fetch(googleSheetCsvUrl);
        if (!response.ok) throw new Error('구글 시트 데이터 로드 실패');
        
        const csvText = await response.text();
        const lines = csvText.split(/\r?\n/);
        const matchedBranches = [];

        for (let i = 1; i < lines.length; i++) {
            if (!lines[i].trim()) continue;
            
            const columns = lines[i].split(",");
            if (columns.length >= 3) {
                const bCategory = columns[0]?.replace(/"/g, "").trim();
                const bName = columns[1]?.replace(/"/g, "").trim();
                const bPostcode = columns[2]?.replace(/"/g, "").trim();
                const bPhone = columns[3]?.replace(/"/g, "").trim() || "연락처 없음";

                if (bPostcode) {
                    let cleanBranchPostcode = bPostcode.padStart(5, '0');
                    let cleanInputPostcode = postcode.padStart(5, '0');

                    if (bCategory === category && cleanBranchPostcode === cleanInputPostcode) {
                        matchedBranches.push({ name: bName, category: bCategory, phone: bPhone });
                    }
                }
            }
        }

        return res.status(200).json({ branches: matchedBranches });

    } catch (error) {
        console.error("서버 내부 오류:", error);
        return res.status(500).json({ error: '데이터를 조회하는 중 서버 오류가 발생했습니다.' });
    }
}
