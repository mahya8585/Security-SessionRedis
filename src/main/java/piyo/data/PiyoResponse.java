package piyo.data;

/**
 * lombokのmodule対応はとても遅れそうなので、
 * Java9以降のバージョンを見据えてgetter/setterべた書きするよー
 */
public class PiyoResponse {

    private String title;
    private String detail;
    private String nextUrl;

    public String getTitle() {
        return title;
    }

    public String getDetail() {
        return detail;
    }

    public String getNextUrl() {
        return nextUrl;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public void setNextUrl(String nextUrl) {
        this.nextUrl = nextUrl;
    }
}
