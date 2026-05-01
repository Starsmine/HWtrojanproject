module shift_reg(
    input clk, rst, shift_in,
    output reg [7:0] data_out
);

always @(posedge clk or posedge rst) begin
    if (rst)
        data_out <= 8'b0;
    else
        data_out <= {data_out[6:0], shift_in};
end
endmodule