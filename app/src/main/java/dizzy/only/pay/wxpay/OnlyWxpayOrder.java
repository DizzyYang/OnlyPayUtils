package dizzy.only.pay.wxpay;

import android.text.TextUtils;
import android.util.Xml;
import com.lzy.okgo.OkGo;
import com.lzy.okgo.callback.StringCallback;
import com.lzy.okgo.model.Response;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Dizzy
 * 2019/6/6 16:16
 * 简介：OnlyWxpayOrder
 */
public class OnlyWxpayOrder {

    private static String mAppId;
    private static String mMchId;
    private static String mApiKey;

    public static void setConfig(String appId, String mchId, String apiKey) {
        mAppId = appId;
        mMchId = mchId;
        mApiKey = apiKey;
    }

    public static void getOrderInfo(String body, String total_fee, String out_trade_no, String notifyUrl, final OnWxpayOrderListener onWxpayOrderListener) {
        try {
            SortedMap<String, String> params = new TreeMap<>();
            params.put("appid", mAppId);
            params.put("body", body);
            params.put("mch_id", mMchId);
            params.put("nonce_str", getNonceStr());
            params.put("notify_url", notifyUrl);
            if (!TextUtils.isEmpty(out_trade_no)) {
                params.put("out_trade_no", out_trade_no);
            } else {
                params.put("out_trade_no", getOutTradeNo());
            }
            params.put("spbill_create_ip", "127.0.0.1");
            params.put("total_fee", total_fee);
            params.put("trade_type", "APP");
            String sign = getSign(params);
            params.put("sign", sign);
            String content = new String(toXml(params).getBytes(), "UTF-8");
            String wxpayUrl = "https://api.mch.weixin.qq.com/pay/unifiedorder";
            OkGo.<String>post(wxpayUrl).upString(content).execute(new StringCallback() {
                @Override
                public void onSuccess(Response<String> response) {
                    Map<String, String> result = decodeXml(response.body());
                    if (result != null) {
                        String return_code = result.get("return_code");
                        if (TextUtils.equals(return_code, "SUCCESS")) {
                            String result_code = result.get("result_code");
                            if (TextUtils.equals(result_code, "SUCCESS")) {
                                try {
                                    String appId = result.get("appid");
                                    String partnerId = result.get("mch_id");
                                    String prepayId = result.get("prepay_id");
                                    String packageValue = "Sign=WXPay";
                                    String nonceStr = getNonceStr();
                                    String timeStamp = getTimeStamp();
                                    SortedMap<String, String> params = new TreeMap<>();
                                    params.put("appid", appId);
                                    params.put("noncestr", nonceStr);
                                    params.put("package", packageValue);
                                    params.put("partnerid", partnerId);
                                    params.put("prepayid", prepayId);
                                    params.put("timestamp", timeStamp);
                                    String sign = getSign(params);
                                    JSONObject object = new JSONObject();
                                    object.put("appId", appId);
                                    object.put("partnerId", partnerId);
                                    object.put("prepayId", prepayId);
                                    object.put("packageValue", packageValue);
                                    object.put("nonceStr", nonceStr);
                                    object.put("timeStamp", timeStamp);
                                    object.put("sign", sign);
                                    if (onWxpayOrderListener != null) {
                                        onWxpayOrderListener.onSuccess(object.toString());
                                    }
                                } catch (JSONException e) {
                                    if (onWxpayOrderListener != null) {
                                        onWxpayOrderListener.onError(e.toString());
                                    }
                                }
                            } else {
                                String err_code_des = result.get("err_code_des");
                                if (onWxpayOrderListener != null) {
                                    onWxpayOrderListener.onError(err_code_des);
                                }
                            }
                        } else {
                            String return_msg = result.get("return_msg");
                            if (onWxpayOrderListener != null) {
                                onWxpayOrderListener.onError(return_msg);
                            }
                        }
                    } else {
                        if (onWxpayOrderListener != null) {
                            onWxpayOrderListener.onError("result=null");
                        }
                    }
                }

                @Override
                public void onError(Response<String> response) {
                    if (onWxpayOrderListener != null) {
                        onWxpayOrderListener.onError(response.getException().toString());
                    }
                }
            });
        } catch (UnsupportedEncodingException e) {
            if (onWxpayOrderListener != null) {
                onWxpayOrderListener.onError(e.toString());
            }
        }
    }

    private static String getSign(Map<String, String> params) {
        List<String> keys = new ArrayList<>(params.keySet());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < params.size(); i++) {
            String key = keys.get(i);
            String value = params.get(key);
            sb.append(key).append('=').append(value).append('&');
        }
        sb.append("key=").append(mApiKey);
        return getMessageDigest(sb.toString().getBytes()).toUpperCase();
    }

    private static String toXml(Map<String, String> params) {
        List<String> keys = new ArrayList<>(params.keySet());
        StringBuilder sb = new StringBuilder();
        sb.append("<xml>");
        for (int i = 0; i < params.size(); i++) {
            String key = keys.get(i);
            String value = params.get(key);
            sb.append("<").append(key).append(">");
            sb.append(value);
            sb.append("</").append(key).append(">");
        }
        sb.append("</xml>");
        return sb.toString();
    }

    private static Map<String, String> decodeXml(String content) {
        try {
            Map<String, String> xml = new HashMap<>();
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(new StringReader(content));
            int event = parser.getEventType();
            while (event != XmlPullParser.END_DOCUMENT) {
                String nodeName = parser.getName();
                switch (event) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        if (!"xml".equals(nodeName)) {
                            xml.put(nodeName, parser.nextText());
                        }
                        break;
                    case XmlPullParser.END_TAG:
                        break;
                }
                event = parser.next();
            }
            return xml;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getNonceStr() {
        Random random = new Random();
        return getMessageDigest(String.valueOf(random.nextInt(10000)).getBytes());
    }

    private static String getOutTradeNo() {
        Random random = new Random();
        return getMessageDigest(String.valueOf(random.nextInt(10000)).getBytes());
    }

    private static String getTimeStamp() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    private static String getMessageDigest(byte[] buffer) {
        char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            MessageDigest mdTemp = MessageDigest.getInstance("MD5");
            mdTemp.update(buffer);
            byte[] md = mdTemp.digest();
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }

    public interface OnWxpayOrderListener {
        void onSuccess(String json);

        void onError(String error);
    }

}
