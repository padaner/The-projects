#include "tree.h"
#include "sha256_.h"
using namespace std;

int main()
{
	string check_str = "";
	vector<string> v;
	string str;
	char a = '0';
  //构建100000个叶子结点的Merkle树
	for (int i = 0; i < 200000; i++)
	{
		str = a;
		v.push_back(str);
		a = a + 1;
	}
	tree ntree;
	ntree.buildBaseLeafes(v);
	cout << "构建Merkle树过程:" << endl << endl;
	ntree.buildTree();
//进行存在或不存在的证明
	cout << endl;
	cout << "想验证的数据: " << endl;
	cin >> check_str; //输入想验证的叶子节点
	check_str = sha2::hash256_hex_string(check_str);

	cout << "想验证的数据的哈希值: " << check_str << endl;

	if (ntree.verify(check_str))//验证有无这个节点 树有无改变
	{
		cout << endl << endl;
		cout << "Merkle树上存在验证的数据的叶子结点" << endl;
	}
	else
	{
		cout << "Merkle树上不存在验证的数据" << endl;
	}
	return 0;
}
