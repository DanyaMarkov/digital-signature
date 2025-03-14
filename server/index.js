const forge = require("node-forge");
const express = require("express");
const bodyParser = require("body-parser");
const app = express();

// Указание порта, на котором будет работать веб-сервер
const PORT = "5000";

app.use(bodyParser.json());

// Генерация пары ключей RSA для сервера
const serverKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
const serverPublicKeyPem = forge.pki.publicKeyToPem(serverKeyPair.publicKey);
const serverPrivateKeyPem = forge.pki.privateKeyToPem(serverKeyPair.privateKey);

// Эндпоинт для получения публичного ключа
app.get("/public-key", (req, res) => {
  res.json({ publicKey: serverPublicKeyPem });
});

// Эндпоинт для верификации подписанного сообщения (сценарий 1)
app.post("/verify-message", (req, res) => {
  const { message, signature, publicKey } = req.body;

  try {
    // Создаем объект открытого ключа из PEM-представления ключа
    // publicKey — это строка, содержащая PEM-кодированный открытый ключ
    const publicKeyObj = forge.pki.publicKeyFromPem(publicKey);

    // Создаем объект для вычисления хеша SHA256
    const md = forge.md.sha256.create();

    // Обновляем объект хеширования сообщением
    // message — это строка, которую нужно проверить на подлинность
    // "utf8" указывает кодировку сообщения
    md.update(message, "utf8");

    // Проверяем подпись.
    // digest().bytes() — получаем байты хеша сообщения
    // forge.util.decode64(signature) — декодируем Base64-представление подписи
    // "RSASSA-PKCS1-V1_5" — алгоритм цифровой подписи
    const verified = publicKeyObj.verify(
      md.digest().bytes(),
      forge.util.decode64(signature),
      "RSASSA-PKCS1-V1_5"
    );

    res.json({ verified: verified });
  } catch (error) {
    console.error("Verification error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Endpoint to generate and sign a random message (Scenario 2)
app.get("/signed-message", (req, res) => {
  // Рандомное сообщение
  const message = "Random message from server: " + Math.random();

  // Создаем объект для вычисления хеша SHA256.
  // forge.md.sha256.create() создает экземпляр алгоритма SHA256.
  const md = forge.md.sha256.create();

  // Обновляем объект хеширования сообщением.
  // md.update() принимает сообщение (message) и кодировку ("utf8") в качестве аргументов.
  // Результатом является вычисление хеша сообщения.
  md.update(message, "utf8");

  // Подписываем хеш сообщения приватным ключом.
  // serverKeyPair.privateKey — это объект приватного ключа.
  // serverKeyPair.privateKey.sign(md) подписывает хэш, вычисленный с помощью md, используя приватный ключ.
  const signature = serverKeyPair.privateKey.sign(md);

  // Кодируем подпись в Base64 для удобства передачи по сети.
  // forge.util.encode64() преобразует бинарные данные подписи в строку, закодированную в Base64.
  const signatureBase64 = forge.util.encode64(signature);

  res.json({ message: message, signature: signatureBase64 });
});

// Функция запуска сервера
const start = async () => {
  try {
    console.log("-----------------------------");
    app.listen(PORT, () => console.log(`Сервер запущен на порте: ${PORT}`));
    console.log("-----------------------------");
  } catch (error) {
    console.log(error);
  }
};

// Запуск сервера
start();
