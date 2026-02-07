function login(token, expectedToken, userInput) {
  if (token === expectedToken) {
    const query = `SELECT * FROM users WHERE name = '${userInput}'`;
    return query;
  }
  document.body.innerHTML = userInput;
}
