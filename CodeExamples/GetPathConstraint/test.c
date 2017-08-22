#include<stdio.h>
int add(int a,int b){
	return a+b;
}
int main() {
	int a,b;
	scanf("%d",&a);
	scanf("%d",&a);
	if(a>0){
		a=add(a,23);
		if(a%3==0){
			b=1;
		}else{
			b=2;
		}
	}else{
		if(a<-10){
			b=3;
		}else{
			b=4;
		}
	}
	return b;
}
