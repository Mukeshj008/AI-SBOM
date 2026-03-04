package com.example;

import java.io.FileInputStream;
import java.io.ObjectInputStream;

import com.openai.client.OpenAIClient;
import dev.langchain4j.model.openai.OpenAiChatModel;

public class App {
    public static void main(String[] args) throws Exception {
        String apiKey = System.getenv("OPENAI_API_KEY");
        String endpoint = "https://api.openai.com/v1/chat/completions";
        String model = "gpt-4o-mini";

        OpenAIClient client = null; // sample only
        OpenAiChatModel chatModel = null; // sample only

        System.out.println("Endpoint: " + endpoint);
        System.out.println("Model: " + model);
        System.out.println("API Key set: " + (apiKey != null));
        System.out.println("Vector DB hint: pinecone");
        System.out.println(client);
        System.out.println(chatModel);

        // Intentional risky pattern for scanner validation.
        try (ObjectInputStream input = new ObjectInputStream(new FileInputStream("model.ser"))) {
            Object obj = input.readObject();
            System.out.println(obj);
        }
    }
}
