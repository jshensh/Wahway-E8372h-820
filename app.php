<?php
require('./vendor/autoload.php');
require('./Wahway.php');

$obj = Wahway::init('http://192.168.8.1', 'password');
// $smsCount = $obj->smsCountContact();
// for ($i = 0; $i < ceil($smsCount / 20); $i++) {
//     var_dump($obj->smsListContact($i + 1));
// }
// var_dump($obj->smsListContact(1));
// var_dump($obj->smsCountPhone('101906'));
// var_dump($obj->smsListPhone('101906'));
// var_dump($obj->smsDelete(['40017']));
// var_dump($obj->smsSend('13800138000', '发送短消息常用Text和PDU(Protocol Data Unit，协议数据单元)模式。使用Text模式收发短信代码简单，实现起来十分容易，但最大的缺点是不能收发中文短信；而PDU模式不仅支持中文短信，也能发送英文短信。PDU模式收发短信可以使用3种编码：7-bit、8-bit和UCS2编码。7-bit编码用于发送普通的ASCII字符，8-bit编码通常用于发送数据消息，UCS2编码用于发送Unicode字符。一般的PDU编码由A B C D E F G H I J K L M十三项组成。'));