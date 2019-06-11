package dizzy.only.pay.wxpay;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import com.tencent.mm.opensdk.constants.ConstantsAPI;
import com.tencent.mm.opensdk.modelbase.BaseReq;
import com.tencent.mm.opensdk.modelbase.BaseResp;
import com.tencent.mm.opensdk.openapi.IWXAPIEventHandler;

/**
 * Dizzy
 * 2019/6/6 16:16
 * 简介：OnlyWxpayActivity
 */
public class OnlyWxpayActivity extends Activity implements IWXAPIEventHandler {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (OnlyWxpay.getInstance().getIWXAPI() != null) {
            OnlyWxpay.getInstance().getIWXAPI().handleIntent(getIntent(), this);
        } else {
            finish();
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (OnlyWxpay.getInstance().getIWXAPI() != null) {
            OnlyWxpay.getInstance().getIWXAPI().handleIntent(intent, this);
        }
    }

    @Override
    public void onReq(BaseReq baseReq) {
    }

    @Override
    public void onResp(BaseResp baseResp) {
        if (baseResp.getType() == ConstantsAPI.COMMAND_PAY_BY_WX) {
            if (OnlyWxpay.getInstance() != null) {
                OnlyWxpay.getInstance().callback(baseResp.errCode);
                finish();
            }
        }
    }

}
