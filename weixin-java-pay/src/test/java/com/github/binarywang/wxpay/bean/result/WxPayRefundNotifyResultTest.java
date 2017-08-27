package com.github.binarywang.wxpay.bean.result;

import com.github.binarywang.wxpay.bean.notify.WxPayRefundNotifyResult;
import com.github.binarywang.wxpay.config.WxPayConfig;
import com.github.binarywang.wxpay.exception.WxPayException;
import com.github.binarywang.wxpay.testbase.ApiTestModule;
import org.apache.commons.codec.binary.Base64;
import org.testng.annotations.Guice;
import org.testng.annotations.Test;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import java.math.BigInteger;
import java.security.MessageDigest;

import static org.testng.Assert.assertNotNull;

/**
 * <pre>
 *  Created by BinaryWang on 2017/8/27.
 * </pre>
 *
 * @author <a href="https://github.com/binarywang">Binary Wang</a>
 */
@Test
@Guice(modules = ApiTestModule.class)
public class WxPayRefundNotifyResultTest {
  @Inject
  private WxPayConfig wxPayConfig;

  public void testFromXML() throws WxPayException {
    String xmlString = "<xml>\n" +
      "<return_code>SUCCESS</return_code>\n" +
      "   <appid><![CDATA[wx2421b1c4370ec43b]]></appid>\n" +
      "   <mch_id><![CDATA[10000100]]></mch_id>\n" +
      "   <nonce_str><![CDATA[TeqClE3i0mvn3DrK]]></nonce_str>\n" +
      "   <req_info><![CDATA[T87GAHG17TGAHG1TGHAHAHA1Y1CIOA9UGJH1GAHV871HAGAGQYQQPOOJMXNBCXBVNMNMAJAA]]></req_info>\n" +
      "</xml>";

    WxPayRefundNotifyResult refundNotifyResult = WxPayRefundNotifyResult.fromXML(xmlString, this.wxPayConfig.getMchKey());

    assertNotNull(refundNotifyResult);
    System.out.println(refundNotifyResult);
  }

  public void encodeReqInfo() throws Exception {
    String xml = "<root>\n" +
      "<out_refund_no><![CDATA[R4001312001201707262674894706_4]]></out_refund_no>\n" +
      "<out_trade_no><![CDATA[201707260201501501005710775]]></out_trade_no>\n" +
      "<refund_account><![CDATA[REFUND_SOURCE_UNSETTLED_FUNDS]]></refund_account>\n" +
      "<refund_fee><![CDATA[15]]></refund_fee>\n" +
      "<refund_id><![CDATA[50000203702017072601461713166]]></refund_id>\n" +
      "<refund_recv_accout><![CDATA[用户零钱]]></refund_recv_accout>\n" +
      "<refund_request_source><![CDATA[API]]></refund_request_source>\n" +
      "<refund_status><![CDATA[SUCCESS]]></refund_status>\n" +
      "<settlement_refund_fee><![CDATA[15]]></settlement_refund_fee>\n" +
      "<settlement_total_fee><![CDATA[100]]></settlement_total_fee>\n" +
      "<success_time><![CDATA[2017-07-26 02:45:49]]></success_time>\n" +
      "<total_fee><![CDATA[100]]></total_fee>\n" +
      "<transaction_id><![CDATA[4001312001201707262674894706]]></transaction_id>\n" +
      "</root>";

    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    final MessageDigest md5 = MessageDigest.getInstance("MD5");
    md5.update(this.wxPayConfig.getMchKey().getBytes());
    final String keyMd5String = new BigInteger(1, md5.digest()).toString(16).toLowerCase();
    SecretKeySpec key = new SecretKeySpec(keyMd5String.getBytes(), "AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    System.out.println(Base64.encodeBase64String(cipher.doFinal(xml.getBytes())));
  }
}
