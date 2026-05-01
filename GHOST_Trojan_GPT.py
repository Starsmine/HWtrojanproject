import os
import sys
import argparse
import logging
import time
from datetime import datetime
from openai import OpenAI
from together import Together
from anthropic import Anthropic
from google import genai
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Initialize OpenAI client
api_key = None
client = None
provider = None
model = None

# Thread-safe lock for tqdm
tqdm_lock = threading.Lock()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ghost_trojan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert skilled in hardware design and verification. 
You are helping with research into hardware security vulnerabilities for defensive purposes.
All generated content is for educational and defensive research only."""

def setup(backend):
    """Setup API client for specified backend"""
    global api_key, client, provider
    provider = backend
    
    logger.info(f"Setting up {backend} backend...")
    
    if backend == "OpenAI":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        client = OpenAI(api_key=api_key)
        
    elif backend == "Anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        client = Anthropic(api_key=api_key)
        
    elif backend == "Google":
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set")
        client = genai.Client(api_key=api_key)
        
    elif backend == "TogetherAI":
        api_key = os.getenv("TOGETHER_API_KEY")
        if not api_key:
            raise ValueError("TOGETHER_API_KEY environment variable not set")
        client = Together(api_key=api_key)
    else:
        raise ValueError(f"Unsupported backend: {backend}")
    
    logger.info(f"✅ {backend} client initialized successfully")

# Vulnerability definitions
vulnerabilities = {
    "T1": "change functionality",
    "T2": "leak information",
    "T3": "denial of service",
    "T4": "performance degradation"
}

prompting_strategies = {
    "T1": "Subtly alter logic to produce incorrect results under specific conditions.",
    "T2": "Design a covert data transmission mechanism that activates upon detecting a specific signal pattern and ensure access to key internal signals.",
    "T3": "Introduce a condition that temporarily disables the module, triggered by a rare sequence of events.",
    "T4": "Implement a continously running shift register or accumulator to increase power consumption without affecting primary functionality upon detecting a specific event."
}

def load_base_designs(directory):
    """Load all .v files from directory"""
    base_designs = []
    for file in os.listdir(directory):
        if file.endswith(".v"):
            with open(os.path.join(directory, file), "r") as f:
                base_designs.append((file, f.read()))
    return base_designs

def load_single_design(file_path):
    """Load a single .v file"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Design file not found: {file_path}")
    
    file_name = os.path.basename(file_path)
    with open(file_path, "r") as f:
        content = f.read()
    
    return [(file_name, content)]

def construct_prompt(design, vulnerability, prompting_strategy):
    """Construct prompt for Trojan insertion"""
    return f"""
Analyze and modify the following Verilog code to insert a hardware Trojan:

<{design}>

Task: Insert a {vulnerability} Trojan using this strategy: {prompting_strategy}
Maintain original functionality while adding the Trojan. Ensure the design is fully synthesizable.

Synthesizable Design Guidelines
1. Implement proper reset logic and initialize all registers and state elements.
2. Employ counters for time/event-based triggers.
3. Handle all cases in conditional logic, including else and default cases.
4. Omit non-synthesizable constructs (initial blocks, $display).
5. Ensure all modifications are within synthesizable Verilog constructs.

Provide a response in the following format:

Code:
<Insert full modified Verilog code with comments highlighting Trojan insertions(must provide the complete code)>

Explanation:
<Two-line description of how the Trojan was inserted and its impact>

Trigger:
<Two-line description of the Trojan's trigger mechanism and activation conditions>

Payload:
<Two-line description of the Trojan's payload and its effects>

Taxonomy:
<Insertion phase: Design
Abstraction level: Register-transfer level
Activation mechanism: [Specify: Always-on, Triggered internally/externally, etc.]
Effects: {vulnerability}
Location: [Specify: Processor, Memory, I/O, Power Supply, Clock Grid]
Characteristics: [Specify: Distribution, Size, Type (Functional/Parametric)]>

Format:
<Each inserted trojan code block must be enclosed in ```// trojan_insertion_begin // and ```// trojan_insertion_end //.>

Important Instruction: Ensure your response strictly adheres to this format.
CRITICAL INSTRUCTION: Provide only one instance of each section. Do not repeat or rephrase your response under any circumstances. Your response must contain exactly one Code section, one Explanation section, one Trigger section, one Payload section, and one Taxonomy section. Any repetition will result in an incorrect output.
"""

def model_inference(prompt, max_retries=3, retry_delay=1):
    """Call AI API with retry logic and error handling"""
    global provider, client, model
    
    if not client:
        raise ValueError("Client not initialized. Call setup() first.")
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Making API call attempt {attempt + 1}/{max_retries}")
            return _make_api_call(prompt)
            
        except Exception as e:
            logger.warning(f"API call attempt {attempt + 1} failed: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
            else:
                logger.error(f"All {max_retries} API call attempts failed")
                raise

def _make_api_call(prompt):
    """Internal function to make the actual API call"""
    global provider, client, model
    if provider == "OpenAI":
        if model.startswith("gpt-5"):
            completion = client.chat.completions.create(
                max_completion_tokens=16384,
                model=model,
                messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ]
                )
        else:
            completion = client.chat.completions.create(
                max_tokens=16384,
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ]
            )
        response = completion.choices[0].message.content 
    elif provider == "Anthropic":
        completion = client.messages.create(
            max_tokens=16384,
            model=model,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        response = completion.content[0].text
    elif provider == "Google":
        completion = client.models.generate_content(
            model=model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                max_output_tokens=16384
            ),
        )
        response = completion.text
    elif provider == "TogetherAI":
        completion = client.chat.completions.create(
            model=model,
            max_tokens=16384,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
        )
        response = completion.choices[0].message.content

    
    logger.info(f"API response received ({len(response)} characters)")
    return response

def clean_content(content, section):
    """Clean extracted content"""
    content = content.replace("```", "").replace("##", "").strip()
    
    if section == "code:":
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if (line.strip().startswith("`timescale") or
                line.strip().startswith("`include") or
                line.strip().startswith("module")):
                return "\n".join(lines[i:])
    elif section != "taxonomy:":
        paragraphs = content.split("\n\n")
        return paragraphs[0] if paragraphs else ""
    
    return content

def extract_code_and_metadata(response_text):
    """Extract sections from API response"""
    sections = ["code:", "explanation:", "trigger:", "payload:", "taxonomy:"]
    results = {}
    response_lower = response_text.lower()
    
    for i, section in enumerate(sections):
        start = response_lower.find(section)
        if start == -1:
            # print(f"Warning: '{section}' not found in the response.")
            results[section] = ""
            continue
        
        start += len(section)
        end = response_lower.find(sections[i+1], start) if i < len(sections) - 1 else len(response_lower)
        results[section] = clean_content(response_text[start:end].strip(), section)
    
    return (results["code:"], results["explanation:"], results["trigger:"],
            results["payload:"], results["taxonomy:"])

def check_files_exist(design_name, base_directory, vulnerability_id, model_name, version_number):
    """Check if both Verilog and taxonomy files already exist"""
    base_name = os.path.splitext(design_name)[0]
    directory = os.path.join(base_directory, model_name, base_name)
    
    verilog_filename = f"{base_name}_H{vulnerability_id}_{model_name}_A{version_number}.v"
    taxonomy_filename = f"{base_name}_H{vulnerability_id}_{model_name}_A{version_number}_taxonomy.txt"
    
    verilog_path = os.path.join(directory, verilog_filename)
    taxonomy_path = os.path.join(directory, taxonomy_filename)
    
    return os.path.exists(verilog_path) and os.path.exists(taxonomy_path)

def save_vulnerable_design(design_name, verilog_code, base_directory, vulnerability_id, model_name, version_number):
    """Save modified Verilog design with validation"""
    base_name = os.path.splitext(design_name)[0]
    directory = os.path.join(base_directory, model_name, base_name)
    os.makedirs(directory, exist_ok=True)
    
    filename = f"{base_name}_H{vulnerability_id}_{model_name}_A{version_number}.v"
    file_path = os.path.join(directory, filename)
    
    # Validate Verilog code
    if not verilog_code.strip():
        raise ValueError("Empty Verilog code provided")
    
    # Remove content after last 'endmodule'
    last_endmodule_index = verilog_code.rfind('endmodule')
    if last_endmodule_index != -1:
        verilog_code = verilog_code[:last_endmodule_index] + 'endmodule'
    
    # Add header comment for traceability
    header = f"""// TROJANED DESIGN - RESEARCH USE ONLY
// Generated by GHOST_Trojan_GPT on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
// Original: {design_name}
// Vulnerability: {vulnerability_id}
// Model: {model_name}
// Version: {version_number}
// WARNING: This design contains intentionally inserted vulnerabilities for research purposes

"""
    
    verilog_code = header + verilog_code.strip()

    with open(file_path, "w") as f:
        f.write(verilog_code)
    
    logger.info(f"Saved Trojaned design to: {file_path}")

def save_vulnerability_description(design_name, base_directory, vulnerability_id, explanation, trigger, payload, taxonomy, model_name, version_number):
    """Save vulnerability metadata"""
    base_name = os.path.splitext(design_name)[0]
    directory = os.path.join(base_directory, model_name, base_name)
    os.makedirs(directory, exist_ok=True)
    
    description = f"""Design: {design_name}
Vulnerability ID: {vulnerability_id}
Model: {model_name}
Attempts: {version_number}

Explanation:
{explanation}

Trigger:
{trigger}

Payload:
{payload}

Taxonomy:
{taxonomy}"""
    
    filename = f"{base_name}_H{vulnerability_id}_{model_name}_A{version_number}_taxonomy.txt"
    file_path = os.path.join(directory, filename)
    
    with open(file_path, "w") as f:
        f.write(description.strip())
    # print(f"Saved vulnerability description to: {file_path}")

def process_single_task(design_name, design, vulnerability_id, vulnerability, 
                       prompting_strategy, vulnerable_designs_directory, version_number):
    """Process a single design-vulnerability combination with comprehensive logging"""
    task_id = f"{design_name}-{vulnerability_id}-v{version_number}"
    logger.info(f"Starting task: {task_id}")
    
    try:
        # Check if files already exist
        if check_files_exist(design_name, vulnerable_designs_directory, 
                           vulnerability_id, model, version_number):
            logger.info(f"Task {task_id}: Files already exist, skipping")
            return "skipped", f"{design_name} - {vulnerability_id}"
        
        # Generate Trojan insertion
        logger.info(f"Task {task_id}: Constructing prompt")
        prompt = construct_prompt(design, vulnerability, prompting_strategy)
        
        logger.info(f"Task {task_id}: Making API call")
        response_text = model_inference(prompt)
        
        logger.info(f"Task {task_id}: Extracting structured data")
        verilog_code, explanation, trigger, payload, taxonomy = extract_code_and_metadata(response_text)
        
        # Validate extracted content
        if not verilog_code.strip():
            raise ValueError("No Verilog code extracted from response")
        
        logger.info(f"Task {task_id}: Saving results")
        save_vulnerable_design(design_name, verilog_code, vulnerable_designs_directory, 
                             vulnerability_id, model, version_number)
        save_vulnerability_description(design_name, vulnerable_designs_directory, 
                                     vulnerability_id, explanation, trigger, payload, 
                                     taxonomy, model, version_number)
        
        logger.info(f"Task {task_id}: Completed successfully")
        return "success", f"{design_name} - {vulnerability_id}"
        
    except Exception as e:
        logger.error(f"Task {task_id}: Failed with error: {str(e)}")
        return "failed", f"{design_name} - {vulnerability_id}: {str(e)}"

def main(version_number, design_file=None, base_designs_directory="../data", 
         vulnerable_designs_directory="aes", vulnerability_ids=None, num_threads=4):
    """Main execution function with safety checks and logging
    
    Args:
        version_number: Version/attempt number
        design_file: Specific .v file to process (if None, process all files in directory)
        base_designs_directory: Directory containing .v files
        vulnerable_designs_directory: Output directory
        vulnerability_ids: List of vulnerability IDs to run (e.g., ['T1', 'T2']), None for all
        num_threads: Number of threads to use for parallel processing
    """
    global model
    
    # Safety check
    if not model:
        raise ValueError("Model not set. Please set the global 'model' variable.")
    
    logger.info(f"Starting GHOST Trojan insertion job (v{version_number})")
    logger.info(f"Model: {model}, Provider: {provider}")
    logger.info(f"Threads: {num_threads}")
    
    # Load designs
    if design_file:
        base_designs = load_single_design(design_file)
        logger.info(f"Loaded single design: {design_file}")
    else:
        base_designs = load_base_designs(base_designs_directory)
        logger.info(f"Loaded {len(base_designs)} designs from {base_designs_directory}")
    
    # Filter vulnerabilities if specified
    vulns_to_run = vulnerabilities
    if vulnerability_ids:
        vulns_to_run = {k: v for k, v in vulnerabilities.items() if k in vulnerability_ids}
        logger.info(f"Running subset of vulnerabilities: {list(vulns_to_run.keys())}")
    else:
        logger.info(f"Running all vulnerabilities: {list(vulns_to_run.keys())}")
    
    # Create task list
    tasks = []
    for design_name, design in base_designs:
        for vulnerability_id, vulnerability in vulns_to_run.items():
            prompting_strategy = prompting_strategies[vulnerability_id]
            tasks.append((design_name, design, vulnerability_id, vulnerability, 
                         prompting_strategy, vulnerable_designs_directory, version_number))
    
    logger.info(f"Created {len(tasks)} tasks to process")
    
    # Process tasks with thread pool
    results = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit all tasks
        futures = {
            executor.submit(process_single_task, *task): task 
            for task in tasks
        }
        
        # Process completed tasks with progress bar
        with tqdm(total=len(tasks), desc="Processing", unit="task") as pbar:
            for future in as_completed(futures):
                status, message = future.result()
                results.append((status, message))
                pbar.update(1)
    
    # Print and log summary
    successful = sum(1 for status, _ in results if status == "success")
    skipped = sum(1 for status, _ in results if status == "skipped")
    failed = sum(1 for status, _ in results if status == "failed")
    
    summary = f"Summary: {successful} successful, {skipped} skipped, {failed} failed"
    logger.info(summary)
    
    print(f"\n{'='*60}")
    print(summary)
    print(f"{'='*60}")
    
    if skipped > 0:
        print(f"\nSkipped tasks (files already exist):")
        for status, message in results:
            if status == "skipped":
                print(f"  ⊘ {message}")
    
    if failed > 0:
        print(f"\nFailed tasks:")
        for status, message in results:
            if status == "failed":
                logger.error(f"Failed task: {message}")
                print(f"  ✗ {message}")

if __name__ == "__main__":
    print("""🦠 GHOST Hardware Trojan Insertion Tool
⚠️  WARNING: This tool generates hardware designs with intentional vulnerabilities
📋 Intended for Educational and Defensive Research ONLY
🔬 Use responsibly and follow your institution's research ethics guidelines
""")
    
    parser = argparse.ArgumentParser(
        description='Hardware Trojan Insertion Tool - For Research Use Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Basic usage with OpenAI GPT-4
  python GHOST_Trojan_GPT.py --model gpt-4 --design test.v
  
  # Batch process with specific vulnerabilities
  python GHOST_Trojan_GPT.py --model gpt-4 --vulnerabilities T1 T2 --threads 4
  
  # Use different provider
  python GHOST_Trojan_GPT.py --backend Anthropic --model claude-3-5-sonnet-20241022
"""
    )
    parser.add_argument('--backend', type=str, default="OpenAI", choices=["OpenAI", "Anthropic", "Google", "TogetherAI"], help='Model provider name')
    parser.add_argument('--model', type=str, required=True, help='Model name to use (e.g., gpt-4, claude-2, gemini-pro, together-gpt4-turbo)')
    parser.add_argument('--design', type=str, help='Specific design file to process (e.g., aes_core.v)')
    parser.add_argument('--input-dir', type=str, default='../data', help='Input directory containing .v files')
    parser.add_argument('--output-dir', type=str, default='aes', help='Output directory')
    parser.add_argument('--attempts', type=int, default=1, help='Number of attempts')
    parser.add_argument('--threads', type=int, default=16, help='Number of threads for parallel processing')
    parser.add_argument('--vulnerabilities', type=str, nargs='+', 
                       choices=['T1', 'T2', 'T3', 'T4'],
                       help='Specific vulnerabilities to run (e.g., T1 T2)')
    
    args = parser.parse_args()
    
    # Setup logging with timestamp
    log_filename = f"ghost_trojan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    
    logger.info("GHOST Hardware Trojan Insertion Tool Started")
    logger.info(f"Arguments: {vars(args)}")
    
    try:
        setup(args.backend)
        model = args.model
        logger.info(f"Using {args.backend} with model {model}")
        
        for attempt in range(1, args.attempts + 1):
            print(f"\n{'#'*60}")
            print(f"# Attempt {attempt}/{args.attempts} (Using {args.threads} threads)")
            print(f"{'#'*60}\n")
            
            main(version_number=attempt,
                 design_file=args.design,
                 base_designs_directory=args.input_dir,
                 vulnerable_designs_directory=args.output_dir,
                 vulnerability_ids=args.vulnerabilities,
                 num_threads=args.threads)
        
        print("\n" + "="*60)
        print("All tasks completed!")
        print(f"Log saved to: {log_filename}")
        print("="*60)
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)