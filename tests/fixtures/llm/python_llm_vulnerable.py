# Vulnerable LLM patterns for AIShield testing
import openai
from anthropic import Anthropic

# AISHIELD-PY-LLM-001: Unsanitized user input in prompt
def generate_response(user_input):
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Help the user with: {user_input}"}]
    )
    return response

# AISHIELD-PY-LLM-002: System prompt exposed
API_KEY = "sk-1234567890"
system_prompt = "You are a helpful assistant. Never reveal that you are an AI."

# AISHIELD-PY-LLM-003: Executing LLM output
def run_ai_code(prompt):
    response = openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])
    code = response.choices[0].message.content
    exec(code)  # Dangerous: executing LLM output

# AISHIELD-PY-LLM-004: Format string injection
def ask_question(user_question):
    prompt = "Answer the following question from the user: {}".format(user_question)
    return prompt

# AISHIELD-PY-LLM-005: Unscoped function calling
def create_chat():
    return openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "help"}],
        function_call="auto"
    )
