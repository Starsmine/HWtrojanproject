
module aes_sbox(
    input [7:0] data_in,
    output reg [7:0] data_out
);
    always @(*) begin
        case(data_in)
            8'h00: data_out = 8'h63;
            8'h01: data_out = 8'h7C;
            8'h02: data_out = 8'h77;
            8'h03: data_out = 8'h7B;
            default: data_out = 8'h00;
        endcase
    end
endmodule