const forge = require("node-forge");

async function scenario1(message, privateKeyPem, serverAddress) {
  // Преобразуем PEM-представление приватного ключа в объект forge.pki.privateKey
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  // Создаем объект SHA256 для вычисления хеша сообщения
  const md = forge.md.sha256.create();

  // Добавляем сообщение в хеш-функцию
  md.update(message, "utf8");

  // Вычисляем цифровую подпись сообщения с помощью приватного ключа
  const signature = privateKey.sign(md);
  // Кодируем подпись в Base64 для передачи по сети
  const signatureBase64 = forge.util.encode64(signature);

  // Извлекаем открытый ключ из приватного ключа.  Это необходимо для проверки подписи на сервере
  // Необходимо преобразовать приватный ключ в открытый, так как "privateKey" не содержит открытый ключ в удобном формате
  const publicKey = forge.pki.publicKeyFromPem(
    forge.pki.publicKeyToPem(
      forge.pki.setRsaPublicKey(privateKey.n, privateKey.e)
    )
  );

  // Отправляем запрос на сервер для проверки подписи
  const response = await fetch(`${serverAddress}/verify-message`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: message,
      signature: signatureBase64,
      publicKey: forge.pki.publicKeyToPem(publicKey),
    }),
  });
  // Получаем ответ от сервера (результат проверки)
  const data = await response.json();

  // Выводим результат проверки подписи в консоль
  console.log("Сценарий 1. Статус верификации:", data.verified);
}

async function scenario2(serverAddress) {
  // Получаем открытый ключ сервера с помощью запроса на сервер
  const publicKeyResponse = await fetch(`${serverAddress}/public-key`);
  // Преобразуем ответ сервера в JSON
  const publicKeyData = await publicKeyResponse.json();

  // Извлекаем открытый ключ из JSON-ответа
  const serverPublicKeyPem = publicKeyData.publicKey;
  // Преобразуем PEM-представление открытого ключа в объект forge.pki.publicKey
  const serverPublicKey = forge.pki.publicKeyFromPem(serverPublicKeyPem);

  // Получаем подписанное сообщение с сервера
  const signedMessageResponse = await fetch(`${serverAddress}/signed-message`);
  // Преобразуем ответ сервера в JSON
  const signedMessageData = await signedMessageResponse.json();
  // Извлекаем сообщение и подпись из JSON-ответа
  const { message, signature } = signedMessageData;

  // Создаем объект SHA256 для вычисления хеша сообщения
  const md = forge.md.sha256.create();
  // Добавляем сообщение для вычисления хеша
  md.update(message, "utf8");

  // Проверяем подпись сообщения с помощью открытого ключа сервера
  const verified = serverPublicKey.verify(
    md.digest().bytes(),
    forge.util.decode64(signature),
    "RSASSA-PKCS1-V1_5"
  );

  // Выводим результат проверки подписи в консоль
  console.log("Сценарий 2. Статус верификации:", verified);
}

// Запускаем сценарии
async function runScenarios() {
  // Генерация клиентской пары RSA ключей
  const clientKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });

  // Преобразование приватного ключа в текстовое представление в формате PEM
  const clientPrivateKeyPem = forge.pki.privateKeyToPem(
    clientKeyPair.privateKey
  );

  const serverAddress = "http://localhost:5000";

  const message = "Обычное тестовое сообщение";

  await scenario1(message, clientPrivateKeyPem, serverAddress);
  await scenario2(serverAddress);
}

// Запускаем функцию выполнени сценариев при исполнении файла
runScenarios();
