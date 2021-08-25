extern crate miracl_core;

fn main() {
    let x: Vec<f32> = vec![0.34362, 2.63588, 1.8803, 1.12673, -0.90941, 0.59397, 0.5232, 0.68602];
    let int_x: Vec<i64> = x.iter().map(|&xi| (xi * 100.0).round() as i64).collect(); 
    println!("int_x: {:?}", int_x);

}
