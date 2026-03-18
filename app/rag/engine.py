import os
from dotenv import load_dotenv
from langchain_community.document_loaders import DirectoryLoader, PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS

# Load your API keys from the .env file
load_dotenv()

class SecurityKnowledgeBase:
    def __init__(self):
        # Always use absolute path from project root
        if __name__ == "__main__":
            # Running directly: app/rag/engine.py
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        else:
            # Imported: from app.rag.engine
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        self.path_to_docs = os.path.join(project_root, "data")
        self.persist_directory = os.path.join(project_root, "data", "vector_db")
        self.embeddings = OpenAIEmbeddings()
        self.vector_db = None

    def build_knowledge_base(self):
        """Reads your PDFs and creates the searchable database."""
        print("Loading security policies...")
        
        # 1. Load all PDFs from your data folder
        loader = DirectoryLoader(self.path_to_docs, glob="./*.pdf", loader_cls=PyPDFLoader)
        documents = loader.load()

        # 2. Split long documents into smaller chunks (1000 characters each)
        # This helps the AI find specific answers faster.
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
        chunks = text_splitter.split_documents(documents)

        # 3. Create the Vector Database
        print(f"Creating database with {len(chunks)} text snippets...")
        self.vector_db = FAISS.from_documents(
            documents=chunks, 
            embedding=self.embeddings
        )
        self.vector_db.save_local(self.persist_directory)
        print("Knowledge Base Ready!")

    def query(self, question: str):
        """Search the database for an answer."""
        if not self.vector_db:
            # Load existing database if it wasn't just built
            self.vector_db = FAISS.load_local(
                self.persist_directory, 
                self.embeddings, 
                allow_dangerous_deserialization=True
            )
        
        # Find the top 3 most relevant snippets
        results = self.vector_db.similarity_search(question, k=3)
        return results

# Simple test to run the file directly
if __name__ == "__main__":
    kb = SecurityKnowledgeBase()
    # Uncomment the line below the first time you run this to build the DB
    kb.build_knowledge_base()
    
    #Example search
    print(kb.query("What are the MCP OWASP top 10 requirements for data encryption?"))