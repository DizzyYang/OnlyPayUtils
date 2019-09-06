package dizzy.only.pay.wxpay;

import android.app.Activity;
import com.tencent.mm.opensdk.modelpay.PayReq;
import com.tencent.mm.opensdk.openapi.IWXAPI;
import com.tencent.mm.opensdk.openapi.WXAPIFactory;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Dizzy
 * 2019/6/6 16:16
 * 简介：OnlyWxpay
 */
public class OnlyWxpay {

    public static final String WXPAY_JSON = "支付数据解析异常";
    public static final String WXPAY_ERROR = "支付失败";
    private static OnlyWxpay onlyWxpay;
    private IWXAPI mIwxapi;
    private OnWxpayListener mOnWxpayListener;

    public static OnlyWxpay getInstance() {
        if (onlyWxpay == null) {
            onlyWxpay = new OnlyWxpay();
        }
        return onlyWxpay;
    }

    public void pay(Activity activity, String appId, String orderInfo, OnWxpayListener onWxpayListener) {
        mIwxapi = WXAPIFactory.createWXAPI(activity, null);
        mIwxapi.registerApp(appId);
        this.mOnWxpayListener = onWxpayListener;
        try {
            JSONObject object = new JSONObject(orderInfo);
            PayReq req = new PayReq();
            req.appId = object.optString("appId");
            req.partnerId = object.optString("partnerId");
            req.prepayId = object.optString("prepayId");
            req.packageValue = object.optString("packageValue");
            req.nonceStr = object.optString("nonceStr");
            req.timeStamp = object.optString("timeStamp");
            req.sign = object.optString("sign");
            mIwxapi.sendReq(req);
        } catch (JSONException e) {
            if (onWxpayListener != null) {
                onWxpayListener.onError(WXPAY_JSON);
            }
        }
    }

    public IWXAPI getIWXAPI() {
        return mIwxapi;
    }

    public void callback(int errCode) {
        if (mOnWxpayListener == null) {
            return;
        }
        switch (errCode) {
            case 0:
                mOnWxpayListener.onSuccess();
                break;
            case -1:
                mOnWxpayListener.onError(WXPAY_ERROR);
                break;
            case -2:
                mOnWxpayListener.onCancel();
                break;
        }
    }

    public interface OnWxpayListener {
        void onSuccess();

        void onError(String error);

        void onCancel();
    }

}
