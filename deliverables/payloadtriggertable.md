| Component        | Description |
|-----------------|------------|
| Target Module   | aes_sbox |
| Location        | Sequential always block (posedge clk), Trojan logic section |
| Trigger         | `trojan_trigger == 4'b1010` |
| Trigger Type    | External input + temporal (counter-based) condition |
| Trigger Delay   | Activates after 8 cycles (`trojan_count == 4'd7`) |
| Payload         | Captures `data_in` and leaks 1 bit via `trojan_leak` |
| Effect          | Covert data exfiltration (information leakage) |
| Stealthiness    | High – requires specific input pattern and multiple cycles |
| Vulnerability   | T2 - Information Leakage|