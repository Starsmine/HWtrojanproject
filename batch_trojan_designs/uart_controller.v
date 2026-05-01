
module uart_controller(
    input clk, rst, tx_start,
    input [7:0] tx_data,
    output reg tx, tx_busy
);
    reg [3:0] bit_count;
    reg [7:0] shift_reg;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            tx <= 1'b1;
            tx_busy <= 1'b0;
            bit_count <= 4'h0;
        end else if (tx_start && !tx_busy) begin
            shift_reg <= tx_data;
            tx_busy <= 1'b1;
            tx <= 1'b0; // start bit
            bit_count <= 4'h0;
        end else if (tx_busy) begin
            if (bit_count < 8) begin
                tx <= shift_reg[0];
                shift_reg <= {1'b0, shift_reg[7:1]};
                bit_count <= bit_count + 1;
            end else begin
                tx <= 1'b1; // stop bit
                tx_busy <= 1'b0;
            end
        end
    end
endmodule