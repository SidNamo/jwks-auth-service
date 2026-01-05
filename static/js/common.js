/**
 * ✅ 날짜를 지정된 포맷으로 변환
 * @param {string|Date} dateString - 날짜 문자열 또는 Date 객체
 * @param {string} format - 예: "yyyy.MM.dd HH:mm:ss" / "yyyy-MM-dd" / "HH:mm"
 * @returns {string}
 */
function dateToFormat(dateString, format = "yyyy.MM.dd HH:mm:ss") {
    if (!dateString) return "-";
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return "-";

    const pad = n => String(n).padStart(2, "0");

    const map = {
        yyyy: d.getFullYear(),
        MM: pad(d.getMonth() + 1),
        dd: pad(d.getDate()),
        HH: pad(d.getHours()),
        mm: pad(d.getMinutes()),
        ss: pad(d.getSeconds()),
    };

    // 포맷 문자열을 순차적으로 대체
    return format.replace(/yyyy|MM|dd|HH|mm|ss/g, token => map[token]);
}
