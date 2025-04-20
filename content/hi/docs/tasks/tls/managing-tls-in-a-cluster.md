---
title: क्लस्टर में TLS प्रमाणपत्र प्रबंधित करें
content_type: task
reviewers:
- mikedanese
- beacham
- liggitx
---

<!-- overview -->

कुबरनेट्स एक `certificates.k8s.io` API प्रदान करता है, जो आपको एक ऐसे Certificate Authority (CA) द्वारा हस्ताक्षरित TLS प्रमाणपत्र जारी करने की अनुमति देता है जिसे आप नियंत्रित करते हैं। ये CA और प्रमाणपत्र आपके वर्कलोड्स को ट्रस्ट स्थापित करने में मदद करते हैं।

`certificates.k8s.io` API एक ऐसे प्रोटोकॉल का उपयोग करता है जो [ACME
ड्राफ्ट](https://github.com/ietf-wg-acme/acme/) के समान है।


{{< note >}}
certificates.k8s.io API का उपयोग करके बनाए गए प्रमाणपत्र एक समर्पित CA
द्वारा हस्ताक्षरित होते हैं। आप अपने क्लस्टर को क्लस्टर रूट CA का उपयोग करने के लिए कॉन्फ़िगर
कर सकते हैं, लेकिन आपको इस पर निर्भर नहीं रहना चाहिए। यह मान लेना कि ये प्रमाणपत्र क्लस्टर
रूट CA के खिलाफ सत्यापित होंगे, एक सुरक्षित धारणा नहीं है।
{{< /note >}}




## {{% heading "आवश्यक शर्तें" %}}


{{< include "task-tutorial-prereqs.md" >}}

आपको `cfssl` टूल की आवश्यकता है। आप `cfssl` को
https://github.com/cloudflare/cfssl/releases से डाउनलोड कर सकते हैं।

इस पृष्ठ के कुछ चरणों में `jq` टूल का उपयोग किया गया है। यदि आपके पास `jq` नहीं है, तो आप
इसे अपने ऑपरेटिंग सिस्टम के सॉफ़्टवेयर स्रोतों के माध्यम से इंस्टॉल कर सकते हैं, या इसे
https://jqlang.github.io/jq/ से प्राप्त कर सकते हैं।

<!-- steps -->

## क्लस्टर में TLS पर भरोसा करना

पॉड के रूप में चल रहे एप्लिकेशन से कस्टम CA पर भरोसा करने के लिए आमतौर पर
कुछ अतिरिक्त एप्लिकेशन कॉन्फ़िगरेशन की आवश्यकता होती है। आपको CA प्रमाणपत्र बंडल
को उन CA प्रमाणपत्रों की सूची में जोड़ना होगा जिन पर TLS क्लाइंट या सर्वर भरोसा करता है। उदाहरण
के लिए, आप इसे गोलेंग TLS कॉन्फ़िगरेशन के साथ प्रमाणपत्र श्रृंखला को पार्स करके और पार्स किए गए
प्रमाणपत्रों को `tls.Config` स्ट्रक्ट में `RootCAs` फ़ील्ड में जोड़कर करेंगे।

{{< note >}}
भले ही कस्टम CA प्रमाणपत्र फ़ाइल सिस्टम में शामिल हो सकता है (कॉन्फिगमेप `kube-root-ca.crt`), में
आपको उस प्रमाणपत्र प्राधिकरण का उपयोग आंतरिक कुबरनेट्स एंडपॉइंट्स को सत्यापित करने के अलावा
किसी अन्य उद्देश्य के लिए नहीं करना चाहिए। आंतरिक कुबरनेट्स एंडपॉइंट का एक उदाहरण डिफ़ॉल्ट
नेमस्पेस में `kubernetes` नामक सर्विस है।

यदि आप अपने वर्कलोड के लिए कस्टम प्रमाणपत्र प्राधिकरण का उपयोग करना चाहते हैं, तो आपको
उस CA को अलग से उत्पन्न करना चाहिए, और उसके CA प्रमाणपत्र को एक
कॉन्फिगमेप का उपयोग करके वितरित करना चाहिए
जिसे आपके पॉड्स पढ़ सकते हैं।
{{< /note >}}

## प्रमाणपत्र का अनुरोध करना

निम्नलिखित अनुभाग दर्शाता है कि DNS के माध्यम से एक्सेस की जाने वाली कुबरनेट्स सर्विस के लिए TLS प्रमाणपत्र कैसे बनाया जाए।

{{< note >}}
यह ट्यूटोरियल CFSSL का उपयोग करता है: क्लॉउडफ्लेर का PKI और TLS टूलकिट, अधिक जानने के लिए यहां क्लिक करें।
{{< /note >}}

## प्रमाणपत्र हस्ताक्षर अनुरोध (CSR) बनाएं

निम्नलिखित कमांड चलाकर एक निजी कुंजी और प्रमाणपत्र हस्ताक्षर अनुरोध (या CSR) उत्पन्न करें:

```shell
cat <<EOF | cfssl genkey - | cfssljson -bare server
{
  "hosts": [
    "my-svc.my-namespace.svc.cluster.local",
    "my-pod.my-namespace.pod.cluster.local",
    "192.0.2.24",
    "10.0.34.2"
  ],
  "CN": "my-pod.my-namespace.pod.cluster.local",
  "key": {
    "algo": "ecdsa",
    "size": 256
  }
}
EOF
```

जहां 192.0.2.24 सर्विस का क्लस्टर आईपी है, my-svc.my-namespace.svc.cluster.local सर्विस का DNS का नाम है, 10.0.34.2 पॉड का आईपी है और my-pod.my-namespace.pod.cluster.local पॉड का DNS का नाम है। आपको इसके समान आउटपुट देखना चाहिए:

```
2022/02/01 11:45:32 [INFO] generate received request
2022/02/01 11:45:32 [INFO] received CSR
2022/02/01 11:45:32 [INFO] generating key: ecdsa-256
2022/02/01 11:45:32 [INFO] encoded CSR
```
यह कमांड दो फाइलें उत्पन्न करता है; यह server.csr उत्पन्न करता है जिसमें PEM एन्कोडेड PKCS#10 प्रमाणन अनुरोध होता है, और server-key.pem जिसमें अभी बनाए जाने वाले प्रमाणपत्र की PEM एन्कोडेड कुंजी होती है।

Kubernetes API को भेजने के लिए एक CertificateSigningRequest ऑब्जेक्ट बनाएं
एक CSR मैनिफ़ेस्ट (YAML में) उत्पन्न करें, और इसे API सर्वर को भेजें। आप निम्नलिखित कमांड चलाकर ऐसा कर सकते हैं:

```
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: my-svc.my-namespace
spec:
  request: $(cat server.csr | base64 | tr -d '\n')
  signerName: example.com/serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF 
```
ध्यान दें कि चरण 1 में बनाई गई server.csr फ़ाइल बेस64 एन्कोडेड है और .spec.request फ़ील्ड में रखी गई है। आप "डिजिटल हस्ताक्षर", "कुंजी एन्सिफरमेंट", और "सर्वर ऑथ" कुंजी उपयोगों के साथ एक प्रमाणपत्र का अनुरोध भी कर रहे हैं, जिसे एक उदाहरण example.com/serving हस्ताक्षरकर्ता द्वारा हस्ताक्षरित किया गया है। एक विशिष्ट signerName का अनुरोध किया जाना चाहिए। अधिक जानकारी के लिए समर्थित हस्ताक्षरकर्ता नामों के लिए दस्तावेज़ देखें।

CSR अब API से लंबित स्थिति में दिखाई देना चाहिए। आप इसे चलाकर देख सकते हैं:

```
kubectl describe csr my-svc.my-namespace
none
Name:                   my-svc.my-namespace
Labels:                 <none>
Annotations:            <none>
CreationTimestamp:      Tue, 01 Feb 2022 11:49:15 -0500
Requesting User:        yourname@example.com
Signer:                 example.com/serving
Status:                 Pending
Subject:
        Common Name:    my-pod.my-namespace.pod.cluster.local
        Serial Number:
Subject Alternative Names:
        DNS Names:      my-pod.my-namespace.pod.cluster.local
                        my-svc.my-namespace.svc.cluster.local
        IP Addresses:   192.0.2.24
                        10.0.34.2
Events: <none>
```
CertificateSigningRequest को स्वीकृत करवाएं {#get-the-certificate-signing-request-approved}
प्रमाणपत्र हस्ताक्षर अनुरोध को स्वीकृत करना या तो एक स्वचालित अनुमोदन प्रक्रिया द्वारा या क्लस्टर प्रशासक द्वारा एक बार के आधार पर किया जाता है। यदि आप प्रमाणपत्र अनुरोध को स्वीकृत करने के लिए अधिकृत हैं, तो आप इसे मैन्युअल रूप से kubectl का उपयोग करके कर सकते हैं; उदाहरण के लिए:

```shell
kubectl certificate approve my-svc.my-namespace
```
```none
certificatesigningrequest.certificates.k8s.io/my-svc.my-namespace approved
```
अब आपको निम्नलिखित देखना चाहिए:

```shell
kubectl get csr
```
```none
NAME                  AGE   SIGNERNAME            REQUESTOR              REQUESTEDDURATION   CONDITION
my-svc.my-namespace   10m   example.com/serving   yourname@example.com   <none>              Approved
```
इसका मतलब है कि प्रमाणपत्र अनुरोध स्वीकृत हो गया है और अनुरोधित हस्ताक्षरकर्ता द्वारा इस पर हस्ताक्षर किए जाने की प्रतीक्षा कर रहा है।

CertificateSigningRequest पर हस्ताक्षर करें {#sign-the-certificate-signing-request}
अगला, आप एक प्रमाणपत्र हस्ताक्षरकर्ता की भूमिका निभाएंगे, प्रमाणपत्र जारी करेंगे, और इसे API पर अपलोड करेंगे।

एक हस्ताक्षरकर्ता आमतौर पर CertificateSigningRequest API को उसके signerName वाले ऑब्जेक्ट्स के लिए देखेगा, जांच करेगा कि वे स्वीकृत हो गए हैं, उन अनुरोधों के लिए प्रमाणपत्रों पर हस्ताक्षर करेगा, और जारी किए गए प्रमाणपत्र के साथ API ऑब्जेक्ट स्थिति को अपडेट करेगा।

एक प्रमाणपत्र प्राधिकरण (CA) बनाएं
नए प्रमाणपत्र पर डिजिटल हस्ताक्षर प्रदान करने के लिए आपको एक प्राधिकरण की आवश्यकता है।

सबसे पहले, निम्नलिखित चलाकर एक हस्ताक्षर प्रमाणपत्र बनाएं:

```shell
cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca
{
  "CN": "My Example Signer",
  "key": {
    "algo": "rsa",
    "size": 2048
  }
}
EOF
```
आपको इसके समान आउटपुट देखना चाहिए:

```none
2022/02/01 11:50:39 [INFO] generating a new CA key and certificate from CSR
2022/02/01 11:50:39 [INFO] generate received request
2022/02/01 11:50:39 [INFO] received CSR
2022/02/01 11:50:39 [INFO] generating key: rsa-2048
2022/02/01 11:50:39 [INFO] encoded CSR
2022/02/01 11:50:39 [INFO] signed certificate with serial number 263983151013686720899716354349605500797834580472
```
यह एक प्रमाणपत्र प्राधिकरण कुंजी फ़ाइल (ca-key.pem) और प्रमाणपत्र (ca.pem) उत्पन्न करता है।

एक प्रमाणपत्र जारी करें
{{% code_sample file="tls/server-signing-config.json" %}}

server-signing-config.json हस्ताक्षर कॉन्फ़िगरेशन और प्रमाणपत्र प्राधिकरण कुंजी फ़ाइल और प्रमाणपत्र का उपयोग करके प्रमाणपत्र अनुरोध पर हस्ताक्षर करें:

```shell
kubectl get csr my-svc.my-namespace -o jsonpath='{.spec.request}' | \
  base64 --decode | \
  cfssl sign -ca ca.pem -ca-key ca-key.pem -config server-signing-config.json - | \
  cfssljson -bare ca-signed-server
```
आपको इसके समान आउटपुट देखना चाहिए:

```plaintext
2022/02/01 11:52:26 [INFO] signed certificate with serial number 576048928624926584381415936700914530534472870337
```
यह एक हस्ताक्षरित सर्विंग प्रमाणपत्र फ़ाइल, ca-signed-server.pem उत्पन्न करता है।

हस्ताक्षरित प्रमाणपत्र अपलोड करें
अंत में, API ऑब्जेक्ट की स्थिति में हस्ताक्षरित प्रमाणपत्र भरें:

```shell
kubectl get csr my-svc.my-namespace -o json | \
  jq '.status.certificate = "'$(base64 ca-signed-server.pem | tr -d '\n')'"' | \
  kubectl replace --raw /apis/certificates.k8s.io/v1/certificatesigningrequests/my-svc.my-namespace/status -f -
```
{{< note >}} यह .status.certificate फ़ील्ड में बेस64-एन्कोडेड सामग्री को भरने के लिए कमांड लाइन टूल jq का उपयोग करता है। यदि आपके पास jq नहीं है, तो आप JSON आउटपुट को एक फ़ाइल में सहेज सकते हैं, इस फ़ील्ड को मैन्युअल रूप से भर सकते हैं, और परिणामी फ़ाइल अपलोड कर सकते हैं। {{< /note >}}

एक बार CSR स्वीकृत हो जाने और हस्ताक्षरित प्रमाणपत्र अपलोड हो जाने के बाद, चलाएँ:

```shell
kubectl get csr
```
आउटपुट इसके समान है:

```none
NAME                  AGE   SIGNERNAME            REQUESTOR              REQUESTEDDURATION   CONDITION
my-svc.my-namespace   20m   example.com/serving   yourname@example.com   <none>              Approved,Issued
```
प्रमाणपत्र डाउनलोड करें और उसका उपयोग करें
अब, अनुरोध करने वाले उपयोगकर्ता के रूप में, आप जारी किए गए प्रमाणपत्र को डाउनलोड कर सकते हैं और निम्नलिखित चलाकर इसे server.crt फ़ाइल में सहेज सकते हैं:

```shell
kubectl get csr my-svc.my-namespace -o jsonpath='{.status.certificate}' \
    | base64 --decode > server.crt
```
अब आप server.crt और server-key.pem को एक {{< glossary_tooltip text="Secret" term_id="secret" >}} में भर सकते हैं जिसे आप बाद में एक पॉड में माउंट कर सकते हैं (उदाहरण के लिए, HTTPS परोसने वाले वेबसर्वर के साथ उपयोग करने के लिए)।

```shell
kubectl create secret tls server --cert server.crt --key server-key.pem
```
```none
secret/server created
```
अंत में, आप ca.pem को एक {{< glossary_tooltip text="ConfigMap" term_id="configmap" >}} में भर सकते हैं और सर्विंग प्रमाणपत्र को सत्यापित करने के लिए इसे ट्रस्ट रूट के रूप में उपयोग कर सकते हैं:

```shell
kubectl create configmap example-serving-ca --from-file ca.crt=ca.pem
```
```none
configmap/example-serving-ca created
```
CertificateSigningRequests को स्वीकृत करना {#approving-certificate-signing-requests}
एक Kubernetes प्रशासक (उचित अनुमतियों के साथ) मैन्युअल रूप से kubectl certificate approve और kubectl certificate deny कमांड का उपयोग करके CertificateSigningRequests को स्वीकृत (या अस्वीकार) कर सकता है। हालाँकि यदि आप इस API का भारी उपयोग करने का इरादा रखते हैं, तो आप एक स्वचालित प्रमाणपत्र नियंत्रक लिखने पर विचार कर सकते हैं।

{{< caution >}} CSRs को स्वीकृत करने की क्षमता यह तय करती है कि आपके परिवेश में कौन किस पर भरोसा करता है। CSRs को स्वीकृत करने की क्षमता व्यापक रूप से या हल्के में नहीं दी जानी चाहिए।

आपको यह सुनिश्चित करना चाहिए कि आप approve अनुमति देने से पहले अनुमोदक पर पड़ने वाली सत्यापन आवश्यकताओं और एक विशिष्ट प्रमाणपत्र जारी करने के परिणामों दोनों को आत्मविश्वास से समझते हैं। {{< /caution >}}

चाहे वह मशीन हो या ऊपर बताए अनुसार kubectl का उपयोग करने वाला इंसान, अनुमोदक की भूमिका यह सत्यापित करना है कि CSR दो आवश्यकताओं को पूरा करता है:

CSR का विषय CSR पर हस्ताक्षर करने के लिए उपयोग की जाने वाली निजी कुंजी को नियंत्रित करता है। यह किसी तीसरे पक्ष द्वारा अधिकृत विषय के रूप में प्रस्तुत होने के खतरे को संबोधित करता है। उपरोक्त उदाहरण में, यह चरण यह सत्यापित करना होगा कि पॉड CSR उत्पन्न करने के लिए उपयोग की जाने वाली निजी कुंजी को नियंत्रित करता है।
CSR का विषय अनुरोधित संदर्भ में कार्य करने के लिए अधिकृत है। यह क्लस्टर में एक अवांछित विषय के शामिल होने के खतरे को संबोधित करता है। उपरोक्त उदाहरण में, यह चरण यह सत्यापित करना होगा कि पॉड को अनुरोधित सेवा में भाग लेने की अनुमति है।
यदि और केवल यदि ये दो आवश्यकताएँ पूरी होती हैं, तो अनुमोदक को CSR को स्वीकृत करना चाहिए और अन्यथा CSR को अस्वीकार करना चाहिए।

प्रमाणपत्र अनुमोदन और एक्सेस नियंत्रण पर अधिक जानकारी के लिए, प्रमाणपत्र हस्ताक्षर अनुरोध संदर्भ पृष्ठ पढ़ें।

हस्ताक्षर प्रदान करने के लिए अपने क्लस्टर को कॉन्फ़िगर करना
यह पृष्ठ मानता है कि प्रमाणपत्र API की सेवा के लिए एक हस्ताक्षरकर्ता स्थापित किया गया है। Kubernetes कंट्रोलर मैनेजर एक हस्ताक्षरकर्ता का डिफ़ॉल्ट कार्यान्वयन प्रदान करता है। इसे सक्षम करने के लिए, कंट्रोलर मैनेजर को --cluster-signing-cert-file और --cluster-signing-key-file पैरामीटर अपने प्रमाणपत्र प्राधिकरण के कीपेयर के पाथ के साथ पास करें।
