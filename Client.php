<?php
namespace phpcent;

class Client
{
    private $url;
    private $apikey;
    private $secret;

    private $cert;
    private $caPath;

    private $connectTimeoutOption;
    private $timeoutOption;

    private static $safety = true;

    /**
     * Client constructor.
     * @param string $url
     * @param string $apikey
     * @param string $secret
     */
    public function __construct($url, $apikey = '', $secret = '')
    {
        $this->url = (string) $url;
        $this->apikey = (string) $apikey;
        $this->secret = (string) $secret;
    }

    /**
     * @param string $key
     * @return $this
     */
    public function setApiKey($key)
    {
        $this->apikey = (string) $key;
        return $this;
    }

    /**
     * @param string $secret
     * @return $this
     */
    public function setSecret($secret)
    {
        $this->secret = (string) $secret;
        return $this;
    }

    public function setSafety($safety)
    {
        self::$safety = (bool) $safety;
        return $this;
    }

    public function setCert($cert) {
        $this->cert = $cert;
        return $this;
    }

    public function setCAPath($caPath) {
        $this->caPath = $caPath;
        return $this;
    }

    /**
     * @param int $connectTimeoutOption
     * @return $this
     */
    public function setConnectTimeoutOption($connectTimeoutOption) {
        $this->connectTimeoutOption = (int) $connectTimeoutOption;
        return $this;
    }

    /**
     * @param int $timeoutOption
     * @return $this
     */
    public function setTimeoutOption($timeoutOption)
    {
        $this->timeoutOption = (int) $timeoutOption;
        return $this;
    }

    /**
     * @param string $channel
     * @param array $data
     * @return mixed
     * @throws \Exception
     */
    public function publish($channel, $data)
    {
        return $this->send('publish', [
            'channel' => (string) $channel,
            'data' => $data,
        ]);
    }

    /**
     * @param string $channels
     * @param array $data
     * @return mixed
     * @throws \Exception
     */
    public function broadcast($channels, $data)
    {
        return $this->send('broadcast', [
            'channels' => (string) $channels,
            'data' => $data,
        ]);
    }

    /**
     * @param string $channel
     * @param string $user
     * @return mixed
     * @throws \Exception
     */
    public function unsubscribe($channel, $user)
    {
        return $this->send('unsubscribe', [
            'channel' => (string) $channel,
            'user' => (string) $user,
        ]);
    }

    /**
     * @param sring $user
     * @return mixed
     * @throws \Exception
     */
    public function disconnect($user)
    {
        return $this->send('disconnect', [
            'user' => (string) $user,
        ]);
    }

    /**
     * @param string $channel
     * @return mixed
     * @throws \Exception
     */
    public function presence($channel)
    {
        return $this->send('presence', [
            'channel' => (string) $channel,
        ]);
    }

    /**
     * @param string $channel
     * @return mixed
     * @throws \Exception
     */
    public function presence_stats($channel)
    {
        return $this->send('presence_stats', [
            'channel' => (string) $channel,
        ]);
    }

    /**
     * @param string $channel
     * @return mixed
     * @throws \Exception
     */
    public function history($channel)
    {
        return $this->send('history', [
            'channel' => (string) $channel,
        ]);
    }

    public function history_remove($channel)
    {
        return $this->send('history_remove', [
            'channel' => $channel,
        ]);
    }

    public function channels()
    {
        return $this->send('channels');
    }

    public function info()
    {
        return $this->send('info');
    }

    /**
     * @param string $userId
     * @param int $exp
     * @param array $info
     * @return string
     */
    public function generateConnectionToken($userId = '', $exp = 0, array $info = [])
    {
        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $payload = ['sub' => (string) $userId];
        if (!empty($info)) $payload['info'] = $info;
        if ($exp) $payload['exp'] = (int) $exp;
        $segments = [];
        $segments[] = $this->urlsafeB64Encode(json_encode($header));
        $segments[] = $this->urlsafeB64Encode(json_encode($payload));
        $signing_input = implode('.', $segments);
        $signature = $this->sign($signing_input, $this->secret);
        $segments[] = $this->urlsafeB64Encode($signature);
        return implode('.', $segments);
    }

    /**
     * @param string $client
     * @param string $channel
     * @param int $exp
     * @param array $info
     * @return string
     */
    public function generatePrivateChannelToken($client, $channel, $exp = 0, array $info = [])
    {
        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $payload = ['channel' => (string) $channel, 'client' => (string) $client];
        if (!empty($info)) $payload['info'] = $info;
        if ($exp) $payload['exp'] = (int) $exp;
        $segments = [];
        $segments[] = $this->urlsafeB64Encode(json_encode($header));
        $segments[] = $this->urlsafeB64Encode(json_encode($payload));
        $signing_input = implode('.', $segments);
        $signature = $this->sign($signing_input, $this->secret);
        $segments[] = $this->urlsafeB64Encode($signature);
        return implode('.', $segments);
    }

    /**
     * @param string $method
     * @param array $params
     * @return mixed
     * @throws \Exception
     */
    private function send($method, array $params = [])
    {
        $response = \json_decode($this->request((string) $method, $params));
        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new \Exception(
                'json_decode error: ' . json_last_error_msg()
            );
        }
        return $response;
    }

    /**
     * @param string $input
     * @return mixed
     */
    private function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode((string) $input), '+/', '-_'));
    }

    private function sign($msg, $key)
    {
        return hash_hmac('sha256', $msg, $key, true);
    }

    /**
     * @param string $method
     * @param array $params
     * @return bool|string
     * @throws \Exception
     */
    private function request($method, array $params)
    {
        $ch = curl_init();
        if ($this->connectTimeoutOption) curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->connectTimeoutOption);
        if ($this->timeoutOption) curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeoutOption);
        if (!self::$safety) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        } elseif (self::$safety) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            if ($this->cert) curl_setopt($ch, CURLOPT_CAINFO, $this->cert);
            if ($this->caPath) curl_setopt($ch, CURLOPT_CAPATH, $this->caPath);
        }
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['method' => $method, 'params' => $params]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->getHeaders());
        curl_setopt($ch, CURLOPT_URL, $this->url);
        $data = curl_exec($ch);
        $error = curl_error($ch);
        $headers = curl_getinfo($ch);
        curl_close($ch);
        if (empty($headers["http_code"]) || ($headers["http_code"] != 200)) {
            throw new \Exception("Response code: "
                . $headers["http_code"]
                . PHP_EOL
                . "cURL error: " . $error . PHP_EOL
                . "Body: "
                . $data
            );
        }
        return $data;
    }

    private function getHeaders()
    {
        return [
            'Content-Type: application/json',
            'Authorization: apikey ' . $this->apikey
        ];
    }
}
