package dizzy.only.pay.alipay;

import android.app.Activity;
import android.os.Handler;
import android.text.TextUtils;
import com.alipay.sdk.app.PayTask;
import java.util.Map;

/**
 * Dizzy
 * 2019/6/6 16:16
 * 简介：OnlyAlipay
 */
public class OnlyAlipay {

    private static final String ALIPAY_NULL = "支付宝返回值异常";
    private static final String ALIPAY_WAIT = "正在处理中，支付结果未知，请联系客服";
    private static final String ALIPAY_ERROR = "支付失败";
    private static OnlyAlipay onlyAlipay;

    public static OnlyAlipay getInstance() {
        if (onlyAlipay == null) {
            onlyAlipay = new OnlyAlipay();
        }
        return onlyAlipay;
    }

    public void pay(Activity activity, final String orderInfo, final OnAlipayListener onAlipayListener) {
        final PayTask payTask = new PayTask(activity);
        final Handler handler = new Handler();
        new Thread(new Runnable() {
            @Override
            public void run() {
                final Map<String, String> result = payTask.payV2(orderInfo, true);
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (result == null) {
                            if (onAlipayListener != null) {
                                onAlipayListener.onError(ALIPAY_NULL);
                            }
                            return;
                        }
                        String status = result.get("resultStatus");
                        callback(status, onAlipayListener);
                    }
                });
            }
        }).start();
    }

    private void callback(String status, OnAlipayListener onAlipayListener) {
        if (onAlipayListener == null) {
            return;
        }
        if (TextUtils.equals(status, "9000")) {
            onAlipayListener.onSuccess();
        } else if (TextUtils.equals(status, "8000") || TextUtils.equals(status, "6004")) {
            onAlipayListener.onError(ALIPAY_WAIT);
        } else {
            onAlipayListener.onError(ALIPAY_ERROR);
        }
    }

    public interface OnAlipayListener {
        void onSuccess();

        void onError(String error);
    }

}
