import OpenAI from "@openai/openai";
import { Pinecone } from "@pinecone-database/pinecone";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const pc = new Pinecone();

async function main() {
  const completion = await client.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [{ role: "user", content: "Write a short poem" }],
  });

  console.log(completion.choices[0]?.message?.content);
  console.log(pc);
}

main();
