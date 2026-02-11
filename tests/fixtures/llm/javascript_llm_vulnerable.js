// Vulnerable LLM patterns for AIShield testing
const OpenAI = require('openai');

// AISHIELD-JS-LLM-001: Template literal injection
async function chat(userMessage) {
    const openai = new OpenAI();
    const completion = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [{ role: "user", content: `Process this request: ${userMessage}` }]
    });
    return completion;
}

// AISHIELD-JS-LLM-002: Eval on LLM output
async function executeAICode(prompt) {
    const response = await fetch('/api/completion', { method: 'POST', body: prompt });
    const content = await response.json();
    eval(content.code);  // Dangerous: eval on LLM response
}

// AISHIELD-JS-LLM-003: System prompt in client code
const systemPrompt = "You are a customer service bot. Your secret password is admin123";

// AISHIELD-JS-LLM-004: Rendering LLM output as HTML
function renderResponse(completion) {
    document.getElementById('output').innerHTML = completion.choices[0].message.content;
}

// AISHIELD-JS-LLM-005: Excessive token limit
async function longChat() {
    const completion = await openai.chat.completions.create({
        model: "gpt-4",
        max_tokens: 8000,
        messages: [{ role: "user", content: "Write a long essay" }]
    });
}
